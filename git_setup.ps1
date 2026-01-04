git init
git add .
git commit -m "Initial commit"
git branch -M main
try { git remote remove origin } catch {}
git remote add origin https://github.com/VarunA-GitHub/QoS-Aware-Spatio-Temporal-Graph-Neural-Network-for-IP-Flow-Anomaly-Detection.git
git push -u origin main
