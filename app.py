from flask import Flask, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
import requests
import time

app = Flask(__name__)

# Connect to MySQL database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@localhost/cve_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database model for CVE data
class CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(255), unique=True, nullable=False)
    source_identifier = db.Column(db.String(255), nullable=False)
    published = db.Column(db.String(255), nullable=False)
    last_modified = db.Column(db.String(255), nullable=False)
    vuln_status = db.Column(db.String(255), nullable=False)

    def as_dict(self):
        """Convert to dictionary for JSON response."""
        return {
            'cve_id': self.cve_id,
            'source_identifier': self.source_identifier,
            'published': self.published,
            'last_modified': self.last_modified,
            'vuln_status': self.vuln_status
        }

# Fetch CVE data from NVD API
def fetch_cve_data(start_index=0, results_per_page=10):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }
    response = requests.get(url, params=params)
    return response.json()

# Sync CVE data to MySQL
def sync_cve_data():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"resultsPerPage": 1000, "startIndex": 0}

    try:
        response = requests.get(url, params=params)
        data = response.json()

        if 'vulnerabilities' in data:
            for item in data['vulnerabilities']:
                cve_data = item['cve']
                cve_id = cve_data['id']
                sourceIdentifier = cve_data.get('sourceIdentifier', 'N/A')  # Fetching identifier
                published = cve_data['published']
                last_modified = cve_data['lastModified']
                vuln_status = cve_data.get('vulnStatus', 'Unknown')  # Get all vulnStatus values

                # Check if CVE already exists
                existing_cve = CVE.query.filter_by(cve_id=cve_id).first()
                if not existing_cve:
                    new_cve = CVE(
                        cve_id=cve_id,
                        source_identifier=sourceIdentifier,
                        published=published,
                        last_modified=last_modified,
                        vuln_status=vuln_status  # Save all statuses
                    )
                    db.session.add(new_cve)

            db.session.commit()
            return jsonify({"message": "Data synchronized successfully"})

        return jsonify({"message": "No vulnerabilities found"}), 404

    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Error fetching data", "details": str(e)}), 500

@app.route('/sync')
def trigger_sync():
    """Manually trigger CVE data synchronization"""
    try:
        sync_cve_data()
        return jsonify({"message": "Data synchronized successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/cves/list', methods=['GET'])
def list_cves():
    """Fetch paginated CVE data from the database."""
    results_per_page = int(request.args.get('resultsPerPage', 10))
    page = int(request.args.get('page', 1))
    offset = (page - 1) * results_per_page
    cves = CVE.query.offset(offset).limit(results_per_page).all()
    total_records = CVE.query.count()

    return jsonify({
        'totalRecords': total_records,
        'cves': [cve.as_dict() for cve in cves]
    })

@app.route('/')
def index():
    """Render the frontend"""
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
