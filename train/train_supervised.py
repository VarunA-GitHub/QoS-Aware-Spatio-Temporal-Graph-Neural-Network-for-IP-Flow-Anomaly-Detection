import torch
import torch.nn as nn
import torch.optim as optim
import os
import sys
from torch.utils.data import WeightedRandomSampler

# Allow importing from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from torch_geometric.loader import DataLoader
from models.qos_stgnn import QoS_STGNN
from sklearn.metrics import f1_score, confusion_matrix

# --- FOCAL LOSS (For Imbalanced Data) ---
class FocalLoss(nn.Module):
    def __init__(self, alpha=None, gamma=2.0):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, inputs, targets):
        import torch.nn.functional as F
        ce_loss = F.cross_entropy(inputs, targets, weight=self.alpha, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = ((1 - pt) ** self.gamma) * ce_loss
        return focal_loss.mean()

def train_model():
    # --- CONFIG ---
    GRAPH_PATH = 'data/processed/graph_snapshots.pt'
    MODEL_SAVE_PATH = 'models/best_model.pth'
    
    # Tuning for 0.93+ F1
    HIDDEN_DIM = 32      # (Effective width = 32 * 8 heads = 256)
    HEADS = 8
    EPOCHS = 100
    LR = 0.001
    BATCH_SIZE = 32      # Smaller batch size for better updates
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"[INFO] Using device: {device}")
    
    # Load Data
    if not os.path.exists(GRAPH_PATH):
        print("[ERROR] Graphs not found.")
        return

    print("[INFO] Loading graphs...")
    snapshots = torch.load(GRAPH_PATH, weights_only=False)
    snapshots = [d for d in snapshots if d.x.shape[0] > 0]

    # Normalize
    all_x = torch.cat([d.x for d in snapshots], dim=0)
    mean = all_x.mean(dim=0)
    std = all_x.std(dim=0)
    std[std == 0] = 1.0
    for d in snapshots:
        d.x = (d.x - mean) / std

    num_features = snapshots[0].x.shape[1]
    all_labels = torch.cat([d.y for d in snapshots])
    num_classes = int(all_labels.max().item()) + 1
    
    # Split
    import random
    random.seed(42)
    indices = list(range(len(snapshots)))
    random.shuffle(indices)
    split = int(0.85 * len(snapshots))
    train_idxs = indices[:split]
    val_idxs = indices[split:]
    
    train_data = [snapshots[i] for i in train_idxs]
    val_data = [snapshots[i] for i in val_idxs]
    
    # --- WEIGHTED SAMPLER (CRITICAL FIX) ---
    print("[INFO] Calculating Sampler Weights...")
    # Calculate weight for each snapshot based on its rarity
    snapshot_weights = []
    for data in train_data:
        # If snapshot has ANY attack (label > 0), boost its weight
        if (data.y > 0).any():
            # Check for super-rare classes (0, 1, 2)
            if (data.y < 3).any():
                weight = 10.0 # Huge boost for rare attacks
            else:
                weight = 5.0  # Boost for common attacks
        else:
            weight = 1.0      # Normal traffic
        snapshot_weights.append(weight)
        
    sampler = WeightedRandomSampler(snapshot_weights, len(snapshot_weights), replacement=True)
    
    # Loaders
    train_loader = DataLoader(train_data, batch_size=BATCH_SIZE, sampler=sampler)
    val_loader = DataLoader(val_data, batch_size=BATCH_SIZE, shuffle=False)
    
    # Model
    model = QoS_STGNN(num_features, HIDDEN_DIM, num_classes, heads=HEADS).to(device)
    optimizer = optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-4)
    
    # Scheduler: OneCycleLR for Super-Convergence
    scheduler = torch.optim.lr_scheduler.OneCycleLR(
        optimizer, max_lr=0.005, epochs=EPOCHS, steps_per_epoch=len(train_loader)
    )
    
    # Loss: Focal Loss
    class_counts = torch.bincount(all_labels, minlength=num_classes).float() + 1
    weights = 1.0 / torch.sqrt(class_counts) # Smooth weights
    weights = weights / weights.sum() * num_classes
    criterion = FocalLoss(alpha=weights.to(device), gamma=2.0)
    
    best_val_f1 = 0.0
    
    print("[INFO] Starting High-Performance Training...")
    
    for epoch in range(EPOCHS):
        model.train()
        total_loss = 0
        
        for data in train_loader:
            data = data.to(device)
            optimizer.zero_grad()
            
            out = model(data)
            loss = criterion(out, data.y)
            loss.backward()
            
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            
            optimizer.step()
            scheduler.step()
            total_loss += loss.item()
            
        avg_loss = total_loss / len(train_loader)
        
        # Validation
        model.eval()
        y_true, y_pred = [], []
        with torch.no_grad():
            for data in val_loader:
                data = data.to(device)
                out = model(data)
                pred = out.argmax(dim=1)
                y_true.extend(data.y.cpu().numpy())
                y_pred.extend(pred.cpu().numpy())
        
        val_f1 = f1_score(y_true, y_pred, average='macro')
        
        print(f"Epoch {epoch+1}/{EPOCHS} | Loss: {avg_loss:.4f} | Val F1: {val_f1:.4f}")
        
        if val_f1 >= best_val_f1:
            best_val_f1 = val_f1
            torch.save(model.state_dict(), MODEL_SAVE_PATH)
            # Only show matrix if results are decent to reduce clutter
            if val_f1 > 0.55:
                 print(f"CM:\n{confusion_matrix(y_true, y_pred)}")
            
    print(f"[DONE] Best Val F1: {best_val_f1:.4f}")

if __name__ == "__main__":
    train_model()
