import _ from 'lodash';
import { olog } from '@optussport/fe-lambda-logger';
import { validateParams } from '../utils/validator';
import { response, isEmail, encrypt } from '../utils/main';
import { invalidParams, invalidEmail } from '../utils/errors';

export const main = async (event) => {
  const log = olog('authStartSession:main');
  try {
    const payload = JSON.parse(_.get(event, 'body', {}));
    log.trace(`original payload ${payload}`);
    const isValid = validateParams(payload, ['email', 'deviceId', 'userAgent']);
    log.trace(`is it valid payload ${isValid}`);
    if (!isValid) {
      return response(
        {
          status: false,
          error: {
            description: 'INVALID_PARAMS',
          },
        },
        401,
      );
    }

    if (!isEmail(payload.email)) {
      return response(invalidEmail, 401);
    }

    const token = await encrypt(payload);
    return response({ status: true, token }, 200);
  } catch (err) {
    log.trace(`error ${err}`);
    return response(invalidParams, 401);
  }
};
