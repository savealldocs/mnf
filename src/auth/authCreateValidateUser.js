// // Used to create a user
import _ from 'lodash';
import { olog } from '@optussport/fe-lambda-logger';
import AWS from 'aws-sdk';
import * as configConstants from '../utils/constants';
import {
  deleteConfirmedUser,
  signUpGenerateCode,
  getUserAttribute,
  response,
  isEmail,
  encrypt,
  isTokenExpired,
  validateToken,
} from '../utils/main';
import { isValidUserMobileNumber, validateParams } from '../utils/validator';
import {
  inValidMobileNumber,
  invalidTokenResponse,
  invalidParams,
  invalidEmail,
  phoneNumberExists,
} from '../utils/errors';

export const main = async (event) => {
  const log = olog('authCreateValidateUser:main');
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
  delete cloneBody.mobileNumber;

  const resp = await validateToken(body.token, cloneBody);
  if (resp) {
    isValidMobile = isValidUserMobileNumber(body.mobileNumber, 'AU');

    // Disabled SG from production
    /*
    log.trace(`going in there- AU ${isValidMobile}`);
    if (!isValidMobile) {
      isValidMobile = isValidUserMobileNumber(body.mobileNumber, 'SG');
    }
    log.trace(`going in there-  SG ${isValidMobile}`);
    */

    if (!isValidMobile) {
      log.trace(`going in there ${inValidMobileNumber}`);
      return response(inValidMobileNumber(body.mobileNumber), 401);
    }
    // if disaster recovery global var is false
    if (configConstants.GLOBAL_DR_MODE === 'false') {
      // // verify if account exists and confirmed
      const isItConfirmedUser = await getUserAttribute(isValidMobile);
      log.trace(`Existing user found with status= ${isItConfirmedUser}`);
      if (isItConfirmedUser) {
        const userDeleted = await deleteConfirmedUser(isValidMobile);
        log.trace(`Confirmed User Deleted with username ${isValidMobile} ${userDeleted}`);
      }
      // finally success case
      cloneBody = _.clone(body);
      delete cloneBody.token;
      log.trace(`before tokenization ${cloneBody}`);
      const token = await encrypt(cloneBody);
      const isCodeGenerated = await signUpGenerateCode(isValidMobile);
      if (isCodeGenerated) {
        return response(
          {
            status: true,
            token: `${token}`,
            mobileNumber: `${body.mobileNumber}`,
          },
          200,
        );
      }
      return response(phoneNumberExists(body.mobileNumber, token), 200);
    }
    // block to manage disaster recovery mode
    cloneBody = _.clone(body);
    delete cloneBody.token;
    log.trace(`before tokenization ${cloneBody}`);
    const token = await encrypt(cloneBody);
    return response(
      {
        status: true,
        token: `${token}`,
        mobileNumber: `${body.mobileNumber}`,
      },
      200,
    );
  }
  return response(invalidTokenResponse(body.mobileNumber), 401);
};
