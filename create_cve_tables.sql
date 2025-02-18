<<<<<<< HEAD
CREATE DATABASE IF NOT EXISTS cve_db;
USE cve_db;

-- Create the CVE table
CREATE TABLE IF NOT EXISTS CVE (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(255) UNIQUE NOT NULL,
    source_identifier VARCHAR(255) NOT NULL,
    published DATE NOT NULL,
    last_modified DATE NOT NULL,
    vuln_status VARCHAR(255) NOT NULL,
    cvss_score FLOAT,
    base_severity VARCHAR(50)
);

-- Create the CVEDescription table
CREATE TABLE IF NOT EXISTS CVE_Description (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(255),
    lang VARCHAR(10) NOT NULL,
    description TEXT NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES CVE(cve_id)
);

-- Create the CVEReference table
CREATE TABLE IF NOT EXISTS CVE_Reference (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(255),
    url VARCHAR(255) NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES CVE(cve_id)
);

-- Create the CVEWeakness table
CREATE TABLE IF NOT EXISTS CVE_Weakness (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(255),
    description TEXT NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES CVE(cve_id)
);
=======
CREATE DATABASE IF NOT EXISTS cve_db;
USE cve_db;

-- Create the CVE table
CREATE TABLE IF NOT EXISTS CVE (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(255) UNIQUE NOT NULL,
    source_identifier VARCHAR(255) NOT NULL,
    published DATE NOT NULL,
    last_modified DATE NOT NULL,
    vuln_status VARCHAR(255) NOT NULL,
    cvss_score FLOAT,
    base_severity VARCHAR(50)
);

-- Create the CVEDescription table
CREATE TABLE IF NOT EXISTS CVEDescription (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(255),
    lang VARCHAR(10) NOT NULL,
    description TEXT NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES CVE(cve_id)
);

-- Create the CVEReference table
CREATE TABLE IF NOT EXISTS CVEReference (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(255),
    url VARCHAR(255) NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES CVE(cve_id)
);

-- Create the CVEWeakness table
CREATE TABLE IF NOT EXISTS CVEWeakness (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(255),
    description TEXT NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES CVE(cve_id)
);
>>>>>>> 8e3c047 (changed paths)
