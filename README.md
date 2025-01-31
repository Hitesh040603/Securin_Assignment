# CVE Data API

This API provides access to Common Vulnerabilities and Exposures (CVE) data retrieved from the National Vulnerability Database (NVD) API. It uses Flask for the API framework, SQLAlchemy for database interaction (MySQL), and requests for fetching data from the NVD.

## Table of Contents

* [Introduction](#introduction)
* [API Endpoints](#api-endpoints)
    * [Sync Data](#sync-data)
    * [List CVEs](#list-cves)
    * [Get CVE Details](#get-cve-details)
* [Data Models](#data-models)
    * [CVE](#cve)
    * [CVEDescription](#cvedescription)
    * [CVEReference](#cvereference)
    * [CVEWeakness](#cveweakness)
* [Error Handling](#error-handling)
* [Running the API](#running-the-api)
* [Deployment](#deployment-optional)
* [Testing](#testing-optional)

<<<<<<< HEAD

## Introduction <a name="introduction"></a>

=======
## Introduction <a name="introduction"></a>

>>>>>>> bc2fd77 (alterred cve_detail.html)
This API simplifies access to CVE data. It fetches data from the NVD's CVE 2.0 API, stores it in a local MySQL database, and provides endpoints for retrieving and displaying the information. This allows for efficient querying and retrieval of CVE details.  It now also includes CVSS scores, severities, and weakness information.

## API Endpoints <a name="api-endpoints"></a>

### Sync Data <a name="sync-data"></a>

* **Endpoint:** `/sync`
* **Method:** `GET`
* **Description:** Synchronizes the local database with the latest CVE data from the NVD API. This endpoint is crucial for keeping the data up-to-date. It fetches data in batches (currently 1000 records per request to NVD) and inserts/updates CVEs, descriptions, references, and weaknesses into the database. It now handles pagination to retrieve all CVEs, not just the first 1000.
* **Request Parameters:** None
* **Response:**
    * `200 OK`:  `{"message": "Data synchronized successfully"}`
    * `500 Internal Server Error`: `{"error": "Error message"}` (e.g., database error, NVD API error)

### List CVEs <a name="list-cves"></a>

* **Endpoint:** `/cves/list`
* **Method:** `GET`
* **Description:** Retrieves a list of CVEs. Supports pagination.
* **Request Parameters:**
    * `resultsPerPage` : Number of results per page (default: 10).
    * `page` : Page number (default: 1).
* **Response:**
    * `200 OK`:
    ```json
    {
      "totalRecords": 123, // Total number of CVEs in the database
      "cves": [
        {
          "cve_id": "CVE-2023-XXXX",
          "source_identifier": "MITRE",
          "published": "2023-10-26",
          "last_modified": "2023-10-27",
          "vuln_status": "Analyzed",
          "cvss_score": 7.5,  // Example CVSS score
          "base_severity": "HIGH" // Example base severity
        },
        // ... more CVE objects
      ]
    }
    ```

### Get CVE Details <a name="get-cve-details"></a>

* **Endpoint:** `/cves/<cve_id>`
* **Method:** `GET`
* **Description:** Retrieves detailed information about a specific CVE. Renders the data using an HTML template (`cve_detail.html`).
* **Request Parameters:**
    * `cve_id` (required): The CVE ID (e.g., CVE-2023-XXXX).
* **Response:**
    * `200 OK`: HTML page displaying CVE details, descriptions, references, and weaknesses.
    * `404 Not Found`: `{"error": "CVE not found"}`

## Data Models <a name="data-models"></a>

### CVE <a name="cve"></a>

| Field             | Type    | Description                                                              |
|-------------------|---------|--------------------------------------------------------------------------|
| `id`              | Integer | Primary key.                                                             |
| `cve_id`          | String  | CVE identifier (e.g., CVE-2023-XXXX).                                  |
| `source_identifier` | String  | Source identifying the vulnerability.                                     |
| `published`         | Date    | Date of publication.                                                      |
| `last_modified`     | Date    | Date of last modification.                                                |
| `vuln_status`       | String  | Status of the vulnerability.                                            |
| `cvss_score`        | Float   | CVSS base score (if available).                                          |
| `base_severity`    | String  | CVSS base severity (if available).                                       |

### CVEDescription <a name="cvedescription"></a>

| Field       | Type    | Description                                         |
|-------------|---------|-----------------------------------------------------|
| `id`          | Integer | Primary key.                                        |
| `cve_id`      | String  | Foreign key referencing CVE.cve_id.                 |
| `lang`        | String  | Language of the description.                         |
| `description` | Text    | Detailed description of the vulnerability.         |

### CVEReference <a name="cvereference"></a>

| Field   | Type    | Description                                   |
|---------|---------|-----------------------------------------------|
| `id`      | Integer | Primary key.                                  |
| `cve_id`  | String  | Foreign key referencing CVE.cve_id.           |
| `url`     | String  | URL reference related to the CVE.             |

### CVEWeakness <a name="cveweakness"></a>

| Field       | Type    | Description                                         |
|-------------|---------|-----------------------------------------------------|
| `id`          | Integer | Primary key.                                        |
| `cve_id`      | String  | Foreign key referencing CVE.cve_id.                 |
| `description` | Text    | Description of the weakness associated with the CVE. |


## Error Handling <a name="error-handling"></a>

The API uses standard HTTP status codes to indicate the outcome of a request. Error responses typically include a JSON object with an "error" key containing a descriptive error message.

## Running the API <a name="running-the-api"></a>

1.  **Clone the repository:** `git clone https://github.com/Hitesh040603/Securin_Assignment`.
2.  **Configure the database:** Update the `SQLALCHEMY_DATABASE_URI` in the code to match your MySQL database credentials.
<<<<<<< HEAD
3.  **Create the database using the script:** .
   `mysql -u root -p cve_db < /path/to/create_cve_tables.sql`
5.  **Run the application:** `python app.py`
=======
3.  **Create the database:** Create the `cve_db` database in MySQL.
4.  **Run the application:** `python app.py`
>>>>>>> bc2fd77 (alterred cve_detail.html)

