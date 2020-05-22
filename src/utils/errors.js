export const INVALID_PARAMETERS = {
  error: {
    id: '',
    code: 'INVALID_PARAMETERS_PROVIDED',
    description: 'Invalid parameters provided',
    reference: '',
  },
};

export const extractVimondError = (res) => {
  const error = res.error || {};
  const errors = error.errors || [];

  if (errors.length > 0) {
    return errors[0];
  }
  return {
    id: error.id,
    code: error.code,
    description: error.description,
    reference: error.reference,
  };
};
export const inValidCode = {
  status: false,
  error: {
    description: 'INVALID_CODE',
  },
};
export const inValidMobileNumber = mobileNumber => ({
  status: false,
  mobileNumber: `${mobileNumber}`,
  error: {
    description: 'INVALID_MOBILE_NUMBER',
  },
});
export const phoneNumberExists = (mobileNumber, token) => ({
  status: false,
  token: `${token}`,
  error: {
    description: 'PHONE_NUMBER_EXISTS',
  },
  mobileNumber: `${mobileNumber}`,
});

export const invalidTokenResponse = mobNumber => ({
  status: false,
  mobileNumber: `${mobNumber}`,
  error: {
    description: 'INVALID_TOKEN',
  },
});

export const invalidParams = {
  status: false,
  error: {
    description: 'INVALID_PARAMS',
  },
};
export const invalidEmail = {
  status: false,
  error: {
    description: 'INVALID_EMAIL',
  },
};

export const reSendCodeFailed = {
  status: false,
  error: {
    description: 'RESEND_CODE_FAILED',
  },
};
