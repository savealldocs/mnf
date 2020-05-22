import _ from 'lodash';
import { olog } from '@optussport/fe-lambda-logger';
import AWS from 'aws-sdk';
import {
  deleteUserAccount,
  validateCode,
  response,
  isEmail,
  isTokenExpired,
  validateToken,
  encrypt,
  updateMobileNumber,
} from '../utils/main';
import * as configConstants from '../utils/constants';
import { isValidUserMobileNumber, validateParams } from '../utils/validator';
import {
  inValidCode, inValidMobileNumber, invalidTokenResponse, invalidParams, invalidEmail,
} from '../utils/errors';

/**
 *
 * @param {*} event
 */
export const main = async (event) => {
  const log = olog('authConfirmSignUp:Main');
  const body = JSON.parse(_.get(event, 'body', {}));
  AWS.config.update({ region: 'ap-southeast-2' });
  let isValidMobile = false;

  const isValid = validateParams(body, ['token', 'email', 'deviceId', 'userAgent', 'mobileNumber', 'code']);
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
  delete cloneBody.code;
  const resp = await validateToken(body.token, cloneBody);
  log.trace(`is it valid token => ${resp}`);
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
    cloneBody = _.clone(body);
    delete cloneBody.token;
    delete cloneBody.code;
    log.trace(`before tokenization ${cloneBody}`);
    const token = await encrypt(cloneBody);
    log.trace(`before tokenization ${token}`);
    if (configConstants.GLOBAL_DR_MODE === 'false') {
      const isValidCode = await validateCode(body.code, isValidMobile);
      log.trace(`isValid code ${isValidCode}`);
      if (isValidCode) {
        if (isValidCode === 'LimitExceededException') {
          return response(
            {
              status: false,
              error: { description: 'LIMIT_EXCEEDED' },
            },
            401,
          );
        }

        // We will attempt to update the mobile number for the user (if they exist already)
        await updateMobileNumber(body.email, isValidMobile);

        // KENH (20th Jan 2020):: Enabled for production as TPS increased enforced on 19th Jan 2020
        // KENH (7th Jan 2020):: Removed due to TPS issues - awaiting on possible increase on pool from AWS
        // Note that on verifyMobile for existing confirmed accounts, a deletion will occur during
        // that workflow
        const isAccountDeleted = await deleteUserAccount(isValidMobile);
        if (isAccountDeleted) {
          return response(
            {
              status: true,
              token: `${token}`,
            },
            200,
          );
        }
        return response(inValidCode, 401);

        // Following block is used if the deleteUserAccount block above is commented out
        /*
        return response(
          {
            status: true,
            token: `${token}`,
          },
          200,
        );
        */
      }
    } else {
      return response(
        {
          status: true,
          token: `${token}`,
        },
        200,
      );
    }

    return response(inValidCode, 401);
  }
  return response(invalidTokenResponse(body.mobileNumber), 401);
};
