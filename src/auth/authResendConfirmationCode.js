// // Used to create a user
import _ from 'lodash';
import { olog } from '@optussport/fe-lambda-logger';
import AWS from 'aws-sdk';
import { isValidUserMobileNumber, validateParams } from '../utils/validator';
import * as configConstants from '../utils/constants';
import {
  generateCode, response, isTokenExpired, validateToken, encrypt, isEmail,
} from '../utils/main';
import {
  reSendCodeFailed,
  inValidMobileNumber,
  invalidTokenResponse,
  invalidParams,
  invalidEmail,
} from '../utils/errors';

export const main = async (event) => {
  const log = olog('authCreateValidateUser:Main');
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
  const resp = await validateToken(body.token, body);
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
    const cloneBody = _.clone(body);
    delete cloneBody.token;
    delete cloneBody.code;
    log.trace(`before tokenization ${cloneBody}`);
    const token = await encrypt(cloneBody);
    if (configConstants.GLOBAL_DR_MODE === 'false') {
      const isCodeGenerated = await generateCode(isValidMobile);
      if (isCodeGenerated === 'LimitExceededException') {
        return response(
          {
            status: false,
            error: { description: 'LIMIT_EXCEEDED' },
          },
          401,
        );
      }
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
      return response(reSendCodeFailed, 401);
    }
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
