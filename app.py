from flask import Flask, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
import requests

app = Flask(__name__)

# Connect to MySQL database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://user:passwrod@localhost/cve_db'
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

    descriptions = db.relationship('CVEDescription', backref='cve', lazy=True)
    references = db.relationship('CVEReference', backref='cve', lazy=True)

    def as_dict(self):
        return {
            'cve_id': self.cve_id,
            'source_identifier': self.source_identifier,
            'published': self.published,
            'last_modified': self.last_modified,
            'vuln_status': self.vuln_status
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

def fetch_cve_data(start_index=0, results_per_page=10):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"resultsPerPage": results_per_page, "startIndex": start_index}
    response = requests.get(url, params=params)
    return response.json()

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
                sourceIdentifier = cve_data.get('sourceIdentifier', 'N/A')
                published = cve_data['published']
                last_modified = cve_data['lastModified']
                vuln_status = cve_data.get('vulnStatus', 'Unknown')

                existing_cve = CVE.query.filter_by(cve_id=cve_id).first()
                if not existing_cve:
                    new_cve = CVE(
                        cve_id=cve_id,
                        source_identifier=sourceIdentifier,
                        published=published,
                        last_modified=last_modified,
                        vuln_status=vuln_status
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

            db.session.commit()
            return jsonify({"message": "Data synchronized successfully"})

        return jsonify({"message": "No vulnerabilities found"}), 404

    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Error fetching data", "details": str(e)}), 500

@app.route('/sync')
def trigger_sync():
    try:
        sync_cve_data()
        return jsonify({"message": "Data synchronized successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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

@app.route('/cves/<cve_id>', methods=['GET'])
def get_cve_details(cve_id):
    cve = CVE.query.filter_by(cve_id=cve_id).first()
    if not cve:
        return jsonify({"error": "CVE not found"}), 404

    descriptions = CVEDescription.query.filter_by(cve_id=cve_id).all()
    references = CVEReference.query.filter_by(cve_id=cve_id).all()

    return render_template(
        'cve_detail.html', 
        cve=cve,
        descriptions=[desc.as_dict() for desc in descriptions],
        references=[ref.as_dict() for ref in references]
    )

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
