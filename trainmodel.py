import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# 📌 Step 1: Expanded Training Data
data = [
    # Critical Severity (Level 3)
    ("System file modification detected in critical system directory", "Critical"),
    ("Firewall detected incoming attack from known malicious IP", "Critical"),
    ("Multiple privileged account creation detected outside business hours", "Critical"),
    ("Ransomware encryption activity detected on file server", "Critical"),
    ("Database server experiencing SQL injection attempts", "Critical"),
    ("Critical vulnerability exploit attempt detected", "Critical"),
    ("Unauthorized access to financial systems detected", "Critical"),
    ("Multiple admin accounts compromised simultaneously", "Critical"),
    ("Directory traversal attack successful on web server", "Critical"),
    ("Authentication server breach detected", "Critical"),
    ("Malware attempting to access encryption keys", "Critical"),
    ("Supply chain compromise detected in vendor software", "Critical"),
    ("Zero-day vulnerability actively exploited on network", "Critical"),
    ("Command and control traffic detected from multiple endpoints", "Critical"),
    ("Persistent backdoor installed on domain controller", "Critical"),
    
    # High Severity (Level 2)
    ("Suspicious login attempt detected from foreign country", "High"),
    ("Malware detected and quarantined on user workstation", "High"),
    ("Brute force attack against admin portal detected", "High"),
    ("Sensitive data exfiltration attempt blocked", "High"),
    ("VPN connection from unusual location for executive account", "High"),
    ("Elevated privileges granted outside change control process", "High"),
    ("Unusual outbound data transfer after hours", "High"),
    ("Web application firewall detected XSS attack attempt", "High"),
    ("Endpoint protection alerted on suspicious script execution", "High"),
    ("DLP system detected potential data breach", "High"),
    ("Multiple account lockouts from same subnet", "High"),
    ("Unauthorized modification to scheduled tasks", "High"),
    ("Security agent disabled on production server", "High"),
    ("Unusual process spawning behavior detected", "High"),
    ("Suspicious registry modifications detected", "High"),
    
    # Medium Severity (Level 1)
    ("Multiple failed login attempts on user account", "Medium"),
    ("New device logged in from unknown location", "Medium"),
    ("User granted admin privileges to application", "Medium"),
    ("Unusual time of access for regular user", "Medium"),
    ("Unexpected software installation on corporate device", "Medium"),
    ("User accessing resources outside of normal pattern", "Medium"),
    ("Non-encrypted connection attempt to secure system", "Medium"),
    ("Multiple password resets in short timeframe", "Medium"),
    ("Developer credentials used from non-developer machine", "Medium"),
    ("Unusual file access pattern detected", "Medium"),
    ("Abnormal login frequency for service account", "Medium"),
    ("Geolocation inconsistency for user login", "Medium"),
    ("Unauthorized port scanning from internal IP", "Medium"),
    ("Shared account used outside business hours", "Medium"),
    ("User downloading unusual file types", "Medium"),
    
    # Low Severity (Level 0)
    ("Regular log entry: System backup completed", "Low"),
    ("Routine password change completed", "Low"),
    ("Scheduled security scan completed", "Low"),
    ("User account added to non-privileged group", "Low"),
    ("Software update deployed successfully", "Low"),
    ("Employee completed security training", "Low"),
    ("Standard maintenance performed on server", "Low"),
    ("Routine database maintenance completed", "Low"),
    ("Test alert from monitoring system", "Low"),
    ("Regular system performance scan", "Low"),
    ("User self-service password reset", "Low"),
    ("Authorized file share access", "Low"),
    ("Regular VPN connection from known location", "Low"),
    ("Normal authentication to corporate applications", "Low"),
    ("Standard user logged in during business hours", "Low")
]

df = pd.DataFrame(data, columns=["message", "severity"])

# Rest of the code remains the same
severity_mapping = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
df["severity"] = df["severity"].map(severity_mapping)

# 📌 Step 3: Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(df["message"], df["severity"], test_size=0.2, random_state=42)

# 📌 Step 4: TF-IDF Vectorization
vectorizer = TfidfVectorizer()
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# 📌 Step 5: Train Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_vec, y_train)

# Add evaluation code
from sklearn.metrics import classification_report, accuracy_score
y_pred = model.predict(X_test_vec)
print(f"Model Accuracy: {accuracy_score(y_test, y_pred):.2f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Low", "Medium", "High", "Critical"]))

# 📌 Step 6: Save the Model & Vectorizer
joblib.dump(model, "alert_classifier.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")

print("\n✅ Model training complete! Saved as alert_classifier.pkl and tfidf_vectorizer.pkl")
