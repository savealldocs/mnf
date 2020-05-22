import _ from 'lodash';
import { parsePhoneNumber } from 'libphonenumber-js/mobile';
import { olog } from '@optussport/fe-lambda-logger';

export const isValidUserMobileNumber = (userMobile, countryCode) => {
  const log = olog('validator:isValidUserMobileNumber');
  log.trace(`usermobile :: ${userMobile}`);
  try {
    const parsedUserMobile = parsePhoneNumber(userMobile, countryCode);
    log.trace(
      `new pohone format type:: ${parsedUserMobile.getType()}  mobile country :: ${
        parsedUserMobile.country
      } parsed usermobile :: ${parsedUserMobile.isValid()} }`,
    );
    if (
      parsedUserMobile.country === countryCode
      && parsedUserMobile.isValid()
      && typeof parsedUserMobile !== 'undefined'
      && parsedUserMobile.getType() === 'MOBILE'
      && parsedUserMobile.getType()
    ) {
      log.trace(`valid Au mobile number ${parsedUserMobile.number}`);
      return parsedUserMobile.number;
    }
    log.trace(`Invalid Au mobile number ${parsedUserMobile.number}`);
    return false;
  } catch (err) {
    log.warn(`Warning: parsing user phone number (${userMobile}).`);
    return false;
  }
};

export const validateParams = (payload, params) => {
  const log = olog('validator:isValidUserMobileNumber');
  let isValid = true;
  _.forEach(params, (element) => {
    if (typeof payload[element] === 'undefined' || payload[element].length <= 0) {
      log.trace(`Invalid param ${element}`);
      isValid = false;
      return false;
    }
    return true;
  });

  return isValid;
};
