from active_alchemy import ActiveAlchemy

db = ActiveAlchemy('sqlite:///data/vulns.db')

class CVE(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String, unique=True)
	description = db.Column(db.String(5000))
	notified = db.Column(db.Boolean, unique=False, default=False)
