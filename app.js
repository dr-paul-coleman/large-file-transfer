const restify = require('restify');
const bunyan = require('bunyan');
const jsforce = require("jsforce");
const fs = require('fs');
const cp = require("child_process");
const AWS = require('aws-sdk');
const axios = require("axios");
var FormData = require("form-data");
const getStream = require("get-stream");
const mime = require("mime-types");

const contentVersionUrl = '/services/data/v53.0/sobjects/ContentVersion/';
const username = process.env.ORG_TEST_USER;
let org = null;
const s3  = new AWS.S3({
  accessKeyId: process.env.BUCKETEER_AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.BUCKETEER_AWS_SECRET_ACCESS_KEY,
  region: 'us-east-1',
});

const server = restify.createServer({
    name: 'Salesforce.org SMS Gateway',
    version: '1.0.0',
    "ignoreTrailingSlash": true
});
server.use(restify.plugins.dateParser());
server.use(restify.plugins.acceptParser(server.acceptable));
server.use(restify.plugins.authorizationParser());
server.use(restify.plugins.queryParser({mapParams: true}));
server.use(restify.plugins.fullResponse());
server.use(restify.plugins.bodyParser({maxBodySize: 209715200, mapParams: false})); //200MB limit
server.use(restify.plugins.gzipResponse());
server.use(restify.plugins.throttle({
    burst: 100,
    rate: 50,
    ip: true,
    overrides: {
        '192.168.1.1': {
            rate: 0,        // unlimited
            burst: 0
        }
    }
}));

server.on('after', restify.plugins.auditLogger({
    log: bunyan.createLogger({
        name: 'audit',
        stream: process.stdout
    }),
    event: 'after',
    printLog: true
}));

function validateRequest(req, resp, next) {

    //require https when running in heroku host, otherwise allow localhost access only
    const isHeroku = req.headers["x-forwarded-proto"] === "https" && process.env.DYNO;
    if (isHeroku || !process.env.DYNO) { // force https on remote heroku dynos
        var origin = req.header("Origin");
        resp.header("Access-Control-Allow-Origin", origin);
        resp.header("Access-Control-Allow-Methods", "POST");
        resp.header("Access-Control-Allow-Headers", req.header("Access-Control-Request-Headers"));
        return next();
    } else {
        resp.send(500, {"500": "Unsupported Protocol HTTP"});
        return next(false);
    }
}
function createFormData(record, file) {
    const contentVersion = {
      Title: record.Title,
      PathOnClient: record.PathOnClient,
      Origin: "H",
    };
    const form = new FormData();
    form.setBoundary("boundary_string");
    form.append("entity_content", JSON.stringify(contentVersion), {
      contentType: "application/json",
    });
    form.append("VersionData", file, {
      filename: record.PathOnClient,
      contentType: mime.lookup(record.PathOnClient),
    });
    return form;
  };

function putContentVersion(parentId, record, data) {
    //use multipart form to support complete file size 
    const formData = createFormData(record, data.Body);
    const createResult = await axios({
        method: "POST",
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
        url: contentVersionUrl,
        headers: {
        Authorization: "Bearer " + org.accessToken,
        "Content-Type": `multipart/form-data; boundary=\"boundary_string\"`,
        },
        data: formData,
    });  

    const contentVersion = await org.sobject("ContentVersion").retrieve(createResult.id);

    const linkResult = await org.sobject('ContentDocumentLink').create({
      ContentDocumentId: contentVersion.ContentDocumentId,
      LinkedEntityId: parentId,
      ShareType: 'V'
    });
  
    if (!linkResult.success) {
      bunyan.error(`Failed to link content document for file "${contentVersion.id}"`)
    }
  
    return contentVersion.id
}

function getContentVersion(id, contentType, generateBase64String) {

    const file = await axios({
        method: "GET",
        hostname: process.env.JWT_ORG_URL,
        url: contentVersionUrl + '/' + id + '/VersionData',
        headers: {
          'Authorization': 'Bearer ' + org.accessToken,
          'Content-Type': contentType
        },
        responseType: 'stream'
      });

    if (generateBase64String) {
        return await getStream(file.data, { encoding: "base64" });
    } else {
        return file.data; // return the stream;
    }
}

function getS3File(key, body) 
{
    var params = {
        Key:    key,
        Bucket: process.env.BUCKETEER_BUCKET_NAME
      };
      
    s3.getObject(params, function put(err, data) {
        if (err) bunyan.error(err, err.stack);
        else     return data;
    });
}

function putS3File(key, body) 
{
    var params = {
        Key:    key,
        Bucket: process.env.BUCKETEER_BUCKET_NAME,
        Body:   body,
      };
      
      s3.putObject(params, function put(err, data) {
        if (err) {
          bunyan.error(err, err.stack);
          return;
        } else {
          return data;
        }
      });
}

function routeToSalesforce(req, resp, next) {

    //get s3 file, push to ContentVersion and ContentDocumentLink
    const data = getS3File(req.key);
    putContentVersion(req.key, req.parentId, data);
}

function routeToS3(req, resp, next) {

    //get Salesforce ContentVersion blob, upload to s3
    const file = getContentVersion(req.Id, req.ContentType, false);
    putS3File(req.PathOnClient, file);
    
}

server.get("/transfertosf", validateRequest, routeToSalesforce);
server.post("/transfertos3", validateRequest, routeToS3);

server.get("*", function (req, res, next) {
    return next(new Error("Invalid Request"));
});

const createOrgConnection = function(username, req, resp) {
    //grab sfdx connection attributes to init a jsforce api client
    cp.exec("sfdx force:org:display -u " + username + " --json | ~/vendor/sfdx/jq/jq -r '.result'", (err, stdout) => {
        if (err) {
            bunyan.info(err);
            resp.end();
        } else {
            const {accessToken, instanceUrl } = JSON.parse(stdout);
            if( accessToken.startsWith('00D5e0000019feJ') ) { //ensure target org
                org = new jsforce.Connection({accessToken, instanceUrl});
                resp.end();
            }
        }
    });
}

const doJWTLogin = function(username, password, req, resp) {
    //use sfdx JWT to obtain an org connection and API token
    cp.exec("sfdx force:auth:jwt:grant -i $JWT_CLIENT_ID -f jwt.key -r $JWT_ORG_URL -s -u " + username, (err, stdout) => {
        bunyan.info(stdout);
        if (stdout.startsWith("Successfully authorized")) {
            createOrgConnection(username, password, req, resp);
        } else {
            resp.end();
        }
    });
}

server.listen(process.env.PORT || 5000, function () {
    //Run
    bunyan.info('>>>>>>>>>>>>  Listening on port ' + PORT);

    setTimeout( function() {
        fs.writeFile('jwt.key', process.env.JWT_CERT, function (err) {
            if (err) return bunyan.info(err);
            bunyan.info('jwt cert saved.');

            doJWTLogin(username, '', {}, {end: function () {
                bunyan.info('JWT Login cached for test user');
            }});
        });
    }, 100);
});
