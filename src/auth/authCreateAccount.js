// // Used to create a user
import _ from 'lodash';
import { olog } from '@optussport/fe-lambda-logger';
import AWS from 'aws-sdk';
import { validateParams, isValidUserMobileNumber } from '../utils/validator';
import {
  createAccount, response, isEmail, validateToken, isTokenExpired,
} from '../utils/main';
import {
  inValidMobileNumber, invalidTokenResponse, invalidParams, invalidEmail,
} from '../utils/errors';

export const main = async (event) => {
  const log = olog('authCreateAccount:Main');
  AWS.config.update({ region: 'ap-southeast-2' });
  const body = JSON.parse(_.get(event, 'body', {}));
  let isValidMobile = false;

  const isValid = validateParams(body, ['token', 'email', 'deviceId', 'userAgent']);
  if (!isValid) {
    return response(invalidParams, 401);
  }
  if (!isEmail(body.email)) {
    return response(invalidEmail, 401);
  }

  const tokenExpired = await isTokenExpired(body.token);
  if (tokenExpired) {
    log.trace(`token expired ${tokenExpired}`);
    return response(invalidTokenResponse(body.mobileNumber), 401);
  }
  let cloneBody = _.clone(body);
  delete cloneBody.firstName;
  delete cloneBody.lastName;
  delete cloneBody.password;
  delete cloneBody.userName;
  delete cloneBody.code;
  delete cloneBody.dateOfBirth;

  const resp = await validateToken(body.token, cloneBody);
  if (resp) {
    isValidMobile = isValidUserMobileNumber(body.mobileNumber, 'AU');

    // Disabled SG from production
    /*
    if (!isValidMobile) {
      isValidMobile = isValidUserMobileNumber(body.mobileNumber, 'SG');
    }
    */

    if (!isValidMobile) {
      return response(inValidMobileNumber(body.mobileNumber), 401);
    }
    // finally success case
    cloneBody = _.clone(body);
    delete cloneBody.token;
    delete cloneBody.code;
    log.trace(`before tokenization ${cloneBody}`);
    const res = await createAccount(body);
    if (res) {
      return response({
        status: true,
      });
    }

    return response(invalidParams, 401);
  }
  return response(invalidTokenResponse(body.mobileNumber), 401);
};
