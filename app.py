from flask import Flask, jsonify, request, render_template,redirect
from flask_sqlalchemy import SQLAlchemy
import requests,time

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
    published = db.Column(db.Date, nullable=False)
    last_modified = db.Column(db.Date, nullable=False)
    vuln_status = db.Column(db.String(255), nullable=False)
    cvss_score = db.Column(db.Float)  
    base_severity = db.Column(db.String(50))  
    weaknesses = db.relationship('CVEWeakness', backref='cve')

    def as_dict(self):
        return {
            'cve_id': self.cve_id,
            'source_identifier': self.source_identifier,
            'published': self.published,
            'last_modified': self.last_modified,
            'vuln_status': self.vuln_status,
            'cvss_score': self.cvss_score,  
            'base_severity': self.base_severity  
        }

class CVEDescription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(255), db.ForeignKey('cve.cve_id'), nullable=False)
    lang = db.Column(db.String(10), nullable=False)
    description = db.Column(db.Text, nullable=False)
    
    def as_dict(self):
        return {
            'lang': self.lang,
            'description': self.description
        }


class CVEReference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(255), db.ForeignKey('cve.cve_id'), nullable=False)
    url = db.Column(db.String(255), nullable=False)

    def as_dict(self):
        return {'url': self.url}

class CVEWeakness(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(255), db.ForeignKey('cve.cve_id'), nullable=False)
    description = db.Column(db.Text, nullable=False)

    def as_dict(self):
        return {'description': self.description}

def fetch_cve_data(start_index=0, results_per_page=10):
    """
    fetches data from given nvd endpoint and returns as json
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"resultsPerPage": results_per_page, "startIndex": start_index}
    response = requests.get(url, params=params)
    return response.json()



def sync_cve_data():
    """
    Syncs CVE data from the NVD API and stores it in the local database.
    Loops through multiple pages to fetch all available records.
    Handles API rate limits with retry and incrementally adjusting time between requests
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page = 1000
    start_index = 0
    max_retries = 5  
    while True:
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index
        }

        retries = 0
        while retries < max_retries:
            try:
                print(f"Fetching CVEs from index {start_index}...")  
                response = requests.get(url, params=params)
                
                if response.status_code in [503, 429]:  
                    wait_time = (2 ** retries)  
                    print(f"Rate limited! Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    retries += 1
                    continue  

                response.raise_for_status()  
                break  

            except requests.exceptions.RequestException as e:
                print(f"Error fetching data: {e}")  
                return jsonify({"error": "Error fetching data", "details": str(e)}), 500

        data = response.json()
        if 'vulnerabilities' not in data or not data['vulnerabilities']:
            print("No more vulnerabilities found. Stopping sync.")
            break

        vulnerabilities = data['vulnerabilities']
        print(f"Fetched {len(vulnerabilities)} CVEs from index {start_index}")  # Debug log

        for item in vulnerabilities:
            cve_data = item['cve']
            cve_id = cve_data['id']
            source_identifier = cve_data.get('sourceIdentifier', 'N/A')
            published = cve_data['published']
            last_modified = cve_data['lastModified']
            vuln_status = cve_data.get('vulnStatus', 'Unknown')

            cvss_score = None
            base_severity = None
            if 'metrics' in cve_data and 'cvssMetricV2' in cve_data['metrics']:
                cvss_score = cve_data['metrics']['cvssMetricV2'][0]['cvssData'].get('baseScore')
                base_severity = cve_data['metrics']['cvssMetricV2'][0].get('baseSeverity')

            existing_cve = CVE.query.filter_by(cve_id=cve_id).first()
            if not existing_cve:
                new_cve = CVE(
                    cve_id=cve_id,
                    source_identifier=source_identifier,
                    published=published,
                    last_modified=last_modified,
                    vuln_status=vuln_status,
                    cvss_score=cvss_score,
                    base_severity=base_severity
                )
                db.session.add(new_cve)

                if 'descriptions' in cve_data:
                    for desc in cve_data['descriptions']:
                        new_description = CVEDescription(
                            cve_id=cve_id,
                            lang=desc['lang'],
                            description=desc['value']
                        )
                        db.session.add(new_description)

                if 'references' in cve_data:
                    for ref in cve_data['references']:
                        new_reference = CVEReference(
                            cve_id=cve_id,
                            url=ref['url']
                        )
                        db.session.add(new_reference)

                if 'weaknesses' in cve_data:
                    for weakness in cve_data['weaknesses']:
                        new_weakness = CVEWeakness(
                            cve_id=cve_id,
                            description=weakness['description'][0]['value'] if 'description' in weakness else 'N/A'
                        )
                        db.session.add(new_weakness)

        db.session.commit()

        
        if len(vulnerabilities) < results_per_page:
            print("Fetched the last page of results. Sync complete.")
            break

        start_index += results_per_page

    return jsonify({"message": "Data synchronized successfully"})

@app.route('/sync')
def trigger_sync():
    """
    Loads data into mysql
    """
    try:
        sync_cve_data()
        return jsonify({"message": "Data synchronized successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/cves/list', methods=['GET'])
def list_cves():
    """
    Loads data from mysql and applies filters if applicable
    """
    results_per_page = int(request.args.get('resultsPerPage', 10))
    page = int(request.args.get('page', 1))
    offset = (page - 1) * results_per_page

    query = CVE.query

    # Apply filters
    if request.args.get('cve_id'):
        query = query.filter(CVE.cve_id.like(f"%{request.args['cve_id']}%"))

    if request.args.get('year'):
        query = query.filter(db.extract('year', CVE.published) == int(request.args['year']))

    if request.args.get('score'):
        query = query.filter(CVE.cvss_score >= float(request.args['score']))

    if request.args.get('days'):
        from datetime import datetime, timedelta
        days_ago = datetime.now() - timedelta(days=int(request.args['days']))
        query = query.filter(CVE.last_modified >= days_ago)

    total_records = query.count()
    cves = query.offset(offset).limit(results_per_page).all()

    return jsonify({
        'totalRecords': total_records,
        'cves': [cve.as_dict() for cve in cves]
    })


@app.route('/cves/<cve_id>', methods=['GET'])
def get_cve_details(cve_id):
    """
    Opens cve_details.html for selected cve
    """
    cve = CVE.query.filter_by(cve_id=cve_id).first()
    if not cve:
        return jsonify({"error": "CVE not found"}), 404

    descriptions = CVEDescription.query.filter_by(cve_id=cve_id).all()
    references = CVEReference.query.filter_by(cve_id=cve_id).all()
    weaknesses = CVEWeakness.query.filter_by(cve_id=cve_id).all()

    return render_template(
        'cve_detail.html', 
        cve=cve,
        descriptions=[desc.as_dict() for desc in descriptions],
        references=[ref.as_dict() for ref in references],
        weaknesses=[weakness.as_dict() for weakness in weaknesses]
    )

@app.route('/cve/list')
def index():
    """
    renders home page
    """
    return render_template('index.html')

@app.route('/')
def default():
<<<<<<< HEAD
    """
    Redirects and sets /cve/list as default path
    """
=======
>>>>>>> 8e3c047 (changed paths)
    return redirect('/cve/list') 

if __name__ == '__main__':
    app.run(debug=True)
