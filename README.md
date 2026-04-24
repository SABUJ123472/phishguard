# PhishGuard — Intelligent Real-Time Phishing Threat Analysis Platform

AI-powered phishing URL detection using Random Forest ML, domain analysis, and live threat intelligence.

## Features
- 🤖 Random Forest ML model (20+ features)
- 🧬 Brand similarity detection (typosquatting)
- 🌐 OpenPhish threat intelligence
- 📊 Real-time dashboard with live scan log
- 📷 QR code scanner
- 🔒 SSL/HTTPS checks + entropy analysis

## Tech Stack
- **Backend:** Python, Flask, Scikit-learn
- **Frontend:** HTML, CSS, JavaScript
- **ML:** Random Forest Classifier
- **Deployment:** Render.com

## Local Development

### 1. Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Train the model
```bash
python train_model.py
```

### 3. Run the server
```bash
python app.py
```

### 4. Open in browser
```
http://127.0.0.1:5000
```

## Deploy to Render.com (Free)

### Option 1: Auto-deploy from GitHub

1. Push this repo to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com/)
3. Click **New** → **Web Service**
4. Connect your GitHub repo
5. Render will auto-detect `render.yaml` and deploy

### Option 2: Manual deploy

1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click **New** → **Web Service**
3. Connect your repo or upload files
4. Settings:
   - **Root Directory:** `backend`
   - **Build Command:** `pip install -r requirements.txt && python train_model.py`
   - **Start Command:** `gunicorn app:app`
   - **Python Version:** 3.11

Your live URL will be: `https://phishguard.onrender.com`

## API Endpoints

### `POST /analyze`
Analyze a URL for phishing threats.
```json
{
  "url": "http://secure-paypa1-login.com"
}
```

### `GET /recent?limit=20`
Get recent scan log (real ML results).

### `GET /health`
Check backend status and model load state.

## Project Structure
```
phisgaurd/
├── backend/
│   ├── app.py              # Flask API
│   ├── model.py            # Feature extraction
│   ├── train_model.py      # Model training
│   ├── requirements.txt
│   └── phishing_model.pkl  # Trained model
├── frontend/
│   ├── index.html          # Homepage
│   ├── scanner.html        # URL scanner
│   ├── dashboard.html      # Threat dashboard
│   ├── about.html          # Project info
│   ├── css/style.css
│   └── js/main.js
└── render.yaml             # Render config
```

## License
MIT
