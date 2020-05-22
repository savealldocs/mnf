// Main Common functions
// @TODO: eventually will be moved into npm repo or shared code across microservices
import {
  get, isEmpty, omit, set, _,
} from 'lodash';
import { Parser } from 'xml2js';
import axios from 'axios';
import crypto from 'crypto';
import generatePassword from 'password-generator';
import AWS from 'aws-sdk';
import moment from 'moment';
import { olog } from '@optussport/fe-lambda-logger';
import * as configConstants from './constants';

/**
 * request
 *
 * Function used to dispatch external requests
 *
 * @param String url
 * @param String method
 * @param Object args
 *
 * @returns promised response
 */
export const request = (url, method, args) => {
  const defaultArgs = typeof args !== 'undefined' ? args : {};

  // Add x-forwarded-for header to spoof coming from AUS
  // set(defaultArgs, ['headers', 'X-Forwarded-For'], '203.13.128.125');

  // Force json response type
  set(defaultArgs, ['headers', 'Accept'], 'application/json');

  let parsedArgs = defaultArgs;
  const requestConfig = {};

  // Pick out params and headers and pass as part of request config for (POST|PUT|PATCH) requests
  if (['post', 'put', 'patch'].indexOf(method) !== -1) {
    const headers = get(defaultArgs, 'headers');
    const params = get(defaultArgs, 'params');

    if (!isEmpty(headers)) {
      requestConfig.headers = headers;
    }
    if (!isEmpty(params)) {
      requestConfig.params = params;
    }

    parsedArgs = omit(defaultArgs, ['headers', 'params']);

    // Check if we need to pass parsedArgs differently due to content type other than application/json
    // i.e. application/x-www-form-urlencoded
    if (get(headers, 'Content-Type') === 'application/x-www-form-urlencoded') {
      const data = get(parsedArgs, 'data');
      if (data) {
        parsedArgs = data;
      }
    }
  }

  return axios[method](url, parsedArgs, requestConfig);
};
export const isEmail = email => /^\S+@\S+$/.test(email);
/**
 * response
 *
 * Function used to generate a response by resolving the promise
 *
 * Format of response should:
 * {
 *   "isBase64Encoded": true|false,
 *   "statusCode": httpStatusCode,
 *   "headers": { "headerName": "headerValue", ... },
 *   "multiValueHeaders": { "headerName": ["headerValue", "headerValue2", ...], ... },
 *   "body": "..."
 * }
 *
 * @param Object  res
 * @param Object  formattedData
 * @param Integer code
 *
 * @returns response
 */
export const response = (formattedData, code) => {
  const responseObj = {};

  const resp = get(formattedData, 'response', formattedData);
  const responseHeaders = get(resp, 'headers');
  const data = get(formattedData, 'data', formattedData);

  // Pass back through headers
  if (responseHeaders) {
    responseObj.headers = responseHeaders;
  }

  // Set for cors
  set(responseObj, ['headers', 'Access-Control-Allow-Origin'], '*');

  responseObj.statusCode = code;
  responseObj.body = JSON.stringify(data);

  return Promise.resolve(responseObj);
};

/**
 * transformXmlToJson
 *
 * Function used to transform xml to json
 *
 * @param String xml
 *
 * @returns Return json object
 */
export const transformXmlToJson = (xml, parserOptions) => {
  let xmlTransformed = {};

  if (xml) {
    const defaultParserOptions = typeof parserOptions !== 'undefined'
      ? parserOptions
      : {
        explicitArray: false,
        mergeAttrs: true,
      };
    const xml2jsParser = Parser(defaultParserOptions);

    xml2jsParser.parseString(xml.toString(), (err, result) => {
      if (!err && result) {
        xmlTransformed = result;
      }
    });
  }

  return xmlTransformed;
};

/**
 * parseJwt
 *
 * Used to parse and decode JWT Token into object
 *
 * @param String token
 *
 * @returns Object decoded JWT Token
 */
export const parseJwt = (token) => {
  if (!token) {
    return {};
  }

  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace('-', '+').replace('_', '/');
  const buff = Buffer.from(base64, 'base64');

  return JSON.parse(buff.toString('ascii'));
};

export const base64AESEncrypt = (plaintext, key, iv) => {
  const ivstring = Buffer.from(iv).toString('hex');

  const cipher = crypto.createCipheriv('aes-256-cbc', key, ivstring);

  let ciph = cipher.update(plaintext, 'utf8', 'base64');
  ciph += cipher.final('base64');
  return ciph;
};

export const base64AESDecrypt = (encrypted, key, iv) => {
  const ivstring = Buffer.from(iv).toString('hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, ivstring);

  let txt = decipher.update(encrypted, 'base64', 'utf8');
  txt += decipher.final('utf8');
  return txt;
};

const isStrongEnough = (password) => {
  const minLength = 6;
  const uppercaseMinCount = 3;
  const lowercaseMinCount = 3;
  const numberMinCount = 2;
  const specialMinCount = 2;
  const UPPERCASE_RE = /([A-Z])/g;
  const LOWERCASE_RE = /([a-z])/g;
  const NUMBER_RE = /([\d])/g;
  /*eslint-disable */
  const SPECIAL_CHAR_RE = /([\?\-])/g;
  const NON_REPEATING_CHAR_RE = /([\w\d\?\-])\1{2,}/g;
  /* eslint-enable */
  const uc = password.match(UPPERCASE_RE);
  const lc = password.match(LOWERCASE_RE);
  const n = password.match(NUMBER_RE);
  const sc = password.match(SPECIAL_CHAR_RE);
  const nr = password.match(NON_REPEATING_CHAR_RE);
  return (
    password.length >= minLength
    && !nr
    && uc
    && uc.length >= uppercaseMinCount
    && lc
    && lc.length >= lowercaseMinCount
    && n
    && n.length >= numberMinCount
    && sc
    && sc.length >= specialMinCount
  );
};
/**
 * Generate custom password compatible to aws cognito password policy
 */
export const customPassword = () => {
  const maxLength = 14;
  const minLength = 10;
  let password = '';
  const randomLength = Math.floor(Math.random() * (maxLength - minLength)) + minLength;
  while (!isStrongEnough(password)) {
    /*eslint-disable*/
    password = generatePassword(randomLength, false, /[\w\d\?\-]/);
    /* eslint-enable */
  }
  return password;
};

export const encryptWithKms = (payload) => {
  const log = olog('main:encrypt');
  log.trace(`token expiry time: ${moment().unix()}`);
  const tokenExpiryTime = moment().unix() + configConstants.TOKEN_EXPIRY * 60;
  const payloadClone = _.clone(payload);
  payloadClone.iat = tokenExpiryTime;
  log.trace(`token expiry time: ${payloadClone}`);
  AWS.config.update({ region: 'ap-southeast-2' });
  const kms = new AWS.KMS();
  return new Promise((resolve, reject) => {
    const params = {
      KeyId: configConstants.KEY_ID,
      Plaintext: JSON.stringify(payloadClone).toString('binary'), // The data to encrypt
    };
    log.trace(`kms key generated ${configConstants.KEY_ID}`);
    kms.encrypt(params, (err, data) => {
      if (err) {
        log.trace(`error generated while encrypting token ${err}`);
        reject(err);
      } else {
        resolve(Buffer.from(data.CiphertextBlob, 'binary').toString('base64'));
      }
    });
  });
};

const encryptwithHash = (payload) => {
  const log = olog('main:encrypt');
  log.trace(`token expiry time: ${moment().unix()}`);
  const tokenExpiryTime = moment().unix() + configConstants.TOKEN_EXPIRY * 60;
  const payloadClone = _.clone(payload);
  payloadClone.iat = tokenExpiryTime;
  return base64AESEncrypt(
    JSON.stringify(payloadClone),
    configConstants.TOKEN_ENCRYPTION_SECRET,
    configConstants.TOKEN_ENCRYPTION_IV,
  );
};

const decryptWithKms = (payload) => {
  const kms = new AWS.KMS();
  return new Promise((resolve, reject) => {
    const params = {
      CiphertextBlob: Buffer.from(payload, 'base64'),
    };
    kms.decrypt(params, (err, data) => {
      if (err) {
        reject(err);
      } else {
        resolve(data.Plaintext.toString('binary'));
      }
    });
  });
};

// eslint-disable-next-line max-len
const decryptwithHash = payload => base64AESDecrypt(payload, configConstants.TOKEN_ENCRYPTION_SECRET, configConstants.TOKEN_ENCRYPTION_IV);

export const encrypt = async (payload) => {
  if (configConstants.GLOBAL_DR_MODE === 'true' || configConstants.ENABLE_KMS === 'false') {
    return encryptwithHash(payload);
  }
  return encryptWithKms(payload);
};

export const decrypt = async (payload) => {
  if (configConstants.GLOBAL_DR_MODE === 'true' || configConstants.ENABLE_KMS === 'false') {
    return decryptwithHash(payload);
  }
  return decryptWithKms(payload);
};

export const isTokenExpired = async (token) => {
  const payload = JSON.parse(await decrypt(token));
  if (payload.iat < moment().unix()) {
    return true;
  }
  return false;
};

export const validateToken = async (token, payload) => {
  const log = olog('authCreateValidateUser:generateCode');
  const data = JSON.parse(await decrypt(token));
  // data = _.remove(data.iat);
  const dataClone = _.clone(data);
  const payloadClone = _.clone(payload);
  delete dataClone.iat;
  delete payloadClone.iat;
  delete payloadClone.token;

  log.trace(`final data ${dataClone}`);
  log.trace(`final data ${payloadClone}`);

  if (_.isEqual(dataClone, payloadClone)) {
    log.trace('valid payload');
    return true;
  }
  log.trace('Invalid payload');
  return false;
};

/**
 *
 * @param {*} mobileNumber
 */
export const deleteUserAccount = (mobileNumber) => {
  const log = olog('authConfirmSignUp:deleteUserAccount');
  const cognitoService = new AWS.CognitoIdentityServiceProvider();
  const delParams = {
    UserPoolId: configConstants.COGNITO_USER_POOL_ID,
    Username: mobileNumber,
  };
  log.trace(`trying to delete the account ${delParams}`);
  return cognitoService
    .adminDeleteUser(delParams)
    .promise()
    .then((data) => {
      log.trace(
        `Deleted User with username ${mobileNumber} from   UserPool ${configConstants.COGNITO_USER_POOL_ID}`,
        ['userAuth'],
        data,
      );
      return true;
    })
    .catch((err) => {
      log.error(
        `Error Deleting user with username ${mobileNumber} with ClientID ${configConstants.COGNITO_CLIENT_ID} > ${err}`,
        ['userAuth'],
      );

      log.trace(`error generated${err}`);
      return false;
    });
};

export const validateCode = (code, mobileNumber) => {
  const log = olog('authConfirmSignUp:validateCode');

  const cognitoService = new AWS.CognitoIdentityServiceProvider();
  log.trace(`new pohone format ${mobileNumber}`);
  const params = {
    Username: mobileNumber,
    ConfirmationCode: code,
    ClientId: `${configConstants.COGNITO_CLIENT_ID}`,
    ForceAliasCreation: true,
  };
  log.trace(`params are ${params}`);

  return cognitoService

    .confirmSignUp(params)
    .promise()
    .then((data) => {
      log.trace(
        `Successful New User created with username ${mobileNumber} with  ClientID ${configConstants.COGNITO_CLIENT_ID}`,
        ['userAuth'],
        data,
      );
      return true;
    })
    .catch((err) => {
      log.error(
        `Error confirming user with username ${mobileNumber} with
         ClientID ${configConstants.COGNITO_CLIENT_ID} > ${err}`,
        ['userAuth'],
      );
      log.error(`error generated${err}`);
      if (err.code === 'LimitExceededException') {
        return 'LimitExceededException';
      }
      return false;
    });
};

export const generateCode = (phoneNumber) => {
  const log = olog('authCreateValidateUser:generateCode');
  const cognitoService = new AWS.CognitoIdentityServiceProvider();
  const params = {
    Username: phoneNumber,
    ClientId: `${configConstants.COGNITO_CLIENT_ID}`,
  };

  log.trace(`params are ${params}`);
  return cognitoService
    .resendConfirmationCode(params)
    .promise()
    .then((data) => {
      log.trace(
        `Successful New User created with username ${phoneNumber} with  ClientID ${configConstants.COGNITO_CLIENT_ID}`,
        ['userAuth'],
        data,
      );
      return response('User Created', 200);
    })
    .catch((err) => {
      log.error(
        `Error confirming user with username ${phoneNumber} with ClientID
        ${configConstants.COGNITO_CLIENT_ID} > ${err}`,
        ['userAuth'],
      );
      log.trace(`error generated ${err}`);
      if (err.code === 'LimitExceededException') {
        return 'LimitExceededException';
      }
      return false;
    });
};

/**
 *
 * @param {*} msisdn
 */

export const createAccount = async (body) => {
  const log = olog('authCreateAccount:createAccount');
  const args = {
    password: body.password,
    mobileNumber: body.mobileNumber,
    userName: body.email,
    firstName: body.firstName,
    lastName: body.lastName,
    dateOfBirth: body.dateOfBirth,
  };
  const invalidData = {
    error: {
      id: '',
      code: 'INVALID_PARAMETERS_PROVIDED',
      description: 'Invalid parameters provided',
      reference: '',
    },
  };
  log.trace(`popst args ${args}`);
  return request(`${configConstants.BASE_API_URL}/userauth/users/web`, 'post', args)
    .then((formattedData) => {
      log.trace(formattedData);
      return true;
    })
    .catch((errData) => {
      const rawerror = _.get(errData, 'data', _.get(errData, ['response', 'data'], invalidData));
      log.error(`Error creating creating new user Account > ${rawerror}`, ['userAuth']);
      return false;
    });
};

export const signUpGenerateCode = (phoneNumber) => {
  const log = olog('authCreateValidateUser:generateCode');
  const cognitoService = new AWS.CognitoIdentityServiceProvider();
  const newUserAttributes = [];
  const dataPhoneNumber = {
    Name: 'phone_number',
    Value: phoneNumber,
  };

  log.trace(`password: ${customPassword()}`);
  const params = {
    Username: phoneNumber,
    Password: customPassword(),
    // Password: 'Aqweds12!',
    ClientId: `${configConstants.COGNITO_CLIENT_ID}`,
    UserAttributes: _.concat(newUserAttributes, dataPhoneNumber),
  };

  return cognitoService
    .signUp(params)
    .promise()
    .then((data) => {
      log.trace(
        `Successful New User created with username ${phoneNumber} with  ClientID ${configConstants.COGNITO_CLIENT_ID}`,
        ['userAuth'],
        data,
      );
      return true;
    })
    .catch((err) => {
      log.trace(`error generated ${err}`);
      return false;
    });
};

export const getUserAttribute = async (phoneNumber) => {
  const log = olog('authCreateValidateUser:getUserAttribute');
  const params = {
    Username: phoneNumber,
    UserPoolId: `${configConstants.COGNITO_USER_POOL_ID}`,
  };
  const cognitoService = new AWS.CognitoIdentityServiceProvider();
  return cognitoService
    .adminGetUser(params)
    .promise()
    .then((data) => {
      if (data.UserStatus === 'CONFIRMED') {
        return true;
      }
      return false;
    })
    .catch((err) => {
      log.error(
        `Error creating user with username ${phoneNumber} with ClientID ${configConstants.COGNITO_CLIENT_ID} > ${err}`,
        ['userAuth'],
      );
      // log.trace(`error generated ${err.stack}`);
      return false;
    });
};

export const deleteConfirmedUser = async (phoneNumber) => {
  const log = olog('authCreateValidateUser:deleteConfirmedUser');
  const params = {
    Username: phoneNumber,
    UserPoolId: `${configConstants.COGNITO_USER_POOL_ID}`,
  };
  log.trace(`params are ${params}`);
  const cognitoService = new AWS.CognitoIdentityServiceProvider();
  return cognitoService
    .adminDeleteUser(params)
    .promise()
    .then((data) => {
      log.trace('User Data fetched', ['userAuth'], data);

      if (data.UserStatus === 'CONFIRMED') {
        return true;
      }
      return false;
    })
    .catch((err) => {
      log.error(
        `Error deleting user with username ${phoneNumber} with ClientID ${configConstants.COGNITO_CLIENT_ID} > ${err}`,
        ['userAuth'],
      );
      log.trace(`error generated ${err.stack}`);
      return false;
    });
};

export const updateMobileNumber = (email, phoneNumber) => {
  const log = olog('authCreateValidateUser:updateMobileNumber');

  AWS.config.update({
    region: 'ap-southeast-2',
  });
  const lambda = new AWS.Lambda();

  const params = {
    FunctionName: `fe-ml-user-auth-${configConstants.STAGE}-adminUpdateProfile`,
    Payload: `{ "email": "${email}", "update": { "mobile": "${phoneNumber}" } }`,
    InvocationType: 'Event',
  };

  log.info(`Invoke lambda function: ${params.FunctionName}`);
  return lambda
    .invoke(params)
    .promise()
    .then(() => {
      log.info(`Lambda ${params.FunctionName} was invoked successful.`);
    })
    .catch((err) => {
      log.error(`Failed to invoke ${params.FunctionName}: ${err}`);
    });
};
