from flask import Flask, jsonify, request,render_template
from flask_sqlalchemy import SQLAlchemy
import requests
import time

app = Flask(__name__)

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@localhost/cve_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database model for CVE data
class CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(255), unique=True)
    description = db.Column(db.Text)
    score = db.Column(db.Float)
    published = db.Column(db.String(255))
    last_modified = db.Column(db.String(255))

    def as_dict(self):
        return {
            'cve_id': self.cve_id,
            'description': self.description,
            'score': self.score,
            'published': self.published,
            'last_modified': self.last_modified
        }

# Fetch CVE data from the NVD API
def fetch_cve_data(start_index=0, results_per_page=10):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "format": "NVD_CVE",
        "version": "2.0"
    }
    response = requests.get(url, params=params)
    return response.json()

# Sync CVE data to the database
def sync_cve_data():
    offset = 0
    results_per_page = 10
    while True:
        data = fetch_cve_data(offset, results_per_page)
        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            break
        
        for vuln in vulnerabilities:
            cve_id = vuln['cve']['id']
            description = vuln['cve']['descriptions'][0]['value']
            score = vuln['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'] if vuln['cve']['metrics']['cvssMetricV2'] else None
            published = vuln['cve']['published']
            last_modified = vuln['cve']['lastModified']
            
            # Data cleansing: Check if CVE already exists
            existing_cve = CVE.query.filter_by(cve_id=cve_id).first()
            if not existing_cve:
                new_cve = CVE(cve_id=cve_id, description=description, score=score, published=published, last_modified=last_modified)
                db.session.add(new_cve)
        
        db.session.commit()
        offset += results_per_page
        time.sleep(1)  # To avoid hitting rate limits

@app.route('/cves/list', methods=['GET'])
def list_cves():
    results_per_page = int(request.args.get('resultsPerPage', 10))
    page = int(request.args.get('page', 1))
    offset = (page - 1) * results_per_page
    cves = CVE.query.offset(offset).limit(results_per_page).all()
    total_records = CVE.query.count()
    return jsonify({
        'totalRecords': total_records,
        'cves': [cve.as_dict() for cve in cves]
    })

# Route to trigger data sync (for example purposes)
@app.route('/')
def index():
    return render_template('index.html') 
@app.route('/sync')
def sync_cve_data():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": 100,  # Fetching a larger batch
        "startIndex": 0
    }

    try:
        response = requests.get(url, params=params)
        print("Response Status Code:", response.status_code)
        print("Response Text:", response.text)  # Log the raw response body
        
        # Check if the response is empty
        if response.status_code != 200 or not response.text:
            return jsonify({"error": "Failed to fetch data from the API", "status_code": response.status_code}), 500
        
        # Attempt to parse the JSON response
        data = response.json()
        print("Parsed JSON:", data)

        if 'vulnerabilities' in data:
            for item in data['vulnerabilities']:
                cve_data = item['cve']
                cve_id = cve_data['id']
                description = cve_data['descriptions'][0]['value']
                score = cve_data.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {}).get('baseScore', 0)
                published = cve_data['published']
                last_modified = cve_data['lastModified']
                
                # Check if the CVE already exists to avoid duplicates
                existing_cve = CVE.query.filter_by(cve_id=cve_id).first()
                if not existing_cve:
                    new_cve = CVE(
                        cve_id=cve_id,
                        description=description,
                        score=score,
                        published=published,
                        last_modified=last_modified
                    )
                    db.session.add(new_cve)
            
            db.session.commit()
            return jsonify({"message": "Data synchronized successfully"})
        
        return jsonify({"message": "No vulnerabilities found in the response"}), 404

    except requests.exceptions.RequestException as e:
        print("Error fetching data:", e)
        return jsonify({"error": "Error fetching data from the NVD API", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
