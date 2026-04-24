"""
Run this once to train and save the ML model: python train_model.py
"""
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from model import extract_features, features_to_array

# --- Synthetic training dataset ---
PHISHING_URLS = [
    "http://secure-paypa1-login.com/verify",
    "http://192.168.1.1/bank/login",
    "http://paypal-secure.update-account.com",
    "http://amazon-login.verify-now.net/signin",
    "http://www.google-security-alert.com/login",
    "http://apple-id.confirm-account.info",
    "http://microsoft-support.tech/update",
    "http://login.facebook-secure.com",
    "http://ebay.account-verify.net",
    "http://netflix-billing.update-info.com",
    "http://bankofamerica.secure-login.xyz",
    "http://chase-bank.verify-account.info",
    "http://wellsfargo-alert.com/login",
    "http://dropbox-share.phish.net/file",
    "http://instagram-verify.com/login",
    "http://twitter-support.net/verify",
    "http://linkedin-jobs.phish.com/apply",
    "http://citibank-secure.update.biz",
    "http://secure.paypa1.com@evil.com",
    "http://xn--pypal-4ve.com/login",
    "http://paypai.com/signin",
    "http://amaz0n.com/account",
    "http://g00gle.com/verify",
    "http://micosoft.com/update",
    "http://faceb00k.com/login",
    "http://secure-login-paypal.com/account/verify?user=admin&pass=1234",
    "http://update-your-account-now.com/banking/login",
    "http://free-gift-amazon.com/claim",
    "http://verify-your-identity-now.net/bank",
    "http://account-suspended-login.com/restore",
    "http://login-secure-banking.xyz/auth",
    "http://confirm-payment-details.com/paypal",
    "http://urgent-account-update.net/signin",
    "http://security-alert-google.com/verify",
    "http://apple-support-alert.com/id/verify",
]

SAFE_URLS = [
    "https://www.google.com",
    "https://www.amazon.com/products",
    "https://github.com/user/repo",
    "https://stackoverflow.com/questions",
    "https://www.wikipedia.org/wiki/Python",
    "https://www.youtube.com/watch",
    "https://www.linkedin.com/in/user",
    "https://www.twitter.com/home",
    "https://www.facebook.com",
    "https://www.microsoft.com/en-us",
    "https://www.apple.com/iphone",
    "https://www.netflix.com/browse",
    "https://www.paypal.com/home",
    "https://www.ebay.com/deals",
    "https://www.dropbox.com/home",
    "https://www.instagram.com",
    "https://docs.python.org/3",
    "https://www.reddit.com/r/python",
    "https://www.nytimes.com/news",
    "https://www.bbc.com/news",
    "https://www.cnn.com",
    "https://www.forbes.com",
    "https://www.medium.com",
    "https://www.coursera.org",
    "https://www.udemy.com",
    "https://www.shopify.com",
    "https://www.stripe.com",
    "https://www.twilio.com",
    "https://www.cloudflare.com",
    "https://www.aws.amazon.com",
    "https://www.azure.microsoft.com",
    "https://www.heroku.com",
    "https://www.digitalocean.com",
    "https://www.vercel.com",
    "https://www.netlify.com",
]

def build_dataset():
    X, y = [], []
    for url in PHISHING_URLS:
        f = extract_features(url)
        if f:
            X.append(features_to_array(f))
            y.append(1)
    for url in SAFE_URLS:
        f = extract_features(url)
        if f:
            X.append(features_to_array(f))
            y.append(0)
    return np.array(X), np.array(y)

if __name__ == "__main__":
    print("Building dataset...")
    X, y = build_dataset()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    joblib.dump(model, "phishing_model.pkl")
    print("Model saved to phishing_model.pkl")
