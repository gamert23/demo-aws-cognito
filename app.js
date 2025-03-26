import express from 'express'
import bodyParser from 'body-parser'
import {
  AdminInitiateAuthCommand,
  AdminRespondToAuthChallengeCommand,
  AdminCreateUserCommand,
  AdminGetUserCommand,
  AdminUpdateUserAttributesCommand,
  CognitoIdentityProviderClient,
  ConfirmForgotPasswordCommand,
  DeliveryMediumType,
  GlobalSignOutCommand,
  ForgotPasswordCommand
} from '@aws-sdk/client-cognito-identity-provider'

const app = express()
const port = 3000

const USER_POOL_ID = '<aws-cognito-user-pool-io>'
const CLIENT_ID = '<aws-cognito-client-id>'
const REGION = 'ap-southeast-1'
const client = new CognitoIdentityProviderClient({ region: REGION })

app.use(bodyParser.json())

// DOC: https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/cognito-identity-provider/

// API: Create new user
app.post('/signup', async (req, res) => {
  const { tempPwd, email, phone, firstName, lastName } = req.body
  const params = {
    UserPoolId: USER_POOL_ID,
    Username: email,
    TemporaryPassword: tempPwd,
    UserAttributes: [
      { Name: 'email', Value: email },
      { Name: 'phone_number', Value: phone },
      { Name: 'given_name', Value: firstName },
      { Name: 'family_name', Value: lastName }
    ],
    DesiredDeliveryMediums: [DeliveryMediumType.EMAIL],
    ForceAliasCreation: false,
  }

  try {
    const data = await client.send(new AdminCreateUserCommand(params))
    res.json(data)
  } catch (error) {
    res.json({
      message: error.message
    })
  }
})

// API: Login with temp password (get session)
app.post('/login-temp-pwd', async (req, res) => {
  const { tempPwd, email } = req.body

  const params = {
    AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
    ClientId: CLIENT_ID,
    UserPoolId: USER_POOL_ID,
    AuthParameters: {
      USERNAME: email,
      PASSWORD: tempPwd,
    },
  }

  try {
    const response = await client.send(new AdminInitiateAuthCommand(params))
    console.log("response", response)
    if (response.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
      res.json({
        session: response.Session,
        message: 'User need to change password',
      })
    } else {
      throw new Error('Unexpected challenge type')
    }
  } catch (error) {
    console.log("error", error)
    res.json({
      message: error.message
    })
  }
})

// API: Set new password and verified email and phone
app.post('/set-new-password', async (req, res) => {
  const { email, password, session } = req.body
  const params = {
    ChallengeName: 'NEW_PASSWORD_REQUIRED',
    ClientId: CLIENT_ID,
    UserPoolId: USER_POOL_ID,
    ChallengeResponses: {
      USERNAME: email,
      NEW_PASSWORD: password,
    },
    Session: session,
  }

  try {
    // Set new password
    await client.send(new AdminRespondToAuthChallengeCommand(params))

    const updateParams = {
      UserPoolId: USER_POOL_ID,
      Username: email,
      UserAttributes: [
        { Name: "email_verified", Value: 'true' },
        { Name: "phone_number_verified", Value: 'true' },
      ],
    }

    // Update email and phone verified
    await client.send(new AdminUpdateUserAttributesCommand(updateParams))
    res.json({
      message: 'Set new password successfully'
    })
  } catch(error) {
    console.log("error", error)
    res.json({
      message: error.message
    })
  }
})

// API: Login with permanent password (get access token)
app.post('/login', async (req, res) => {
  const { password, email } = req.body

  const params = {
    AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
    ClientId: CLIENT_ID,
    UserPoolId: USER_POOL_ID,
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
    },
  }

  try {
    const response = await client.send(new AdminInitiateAuthCommand(params))
    res.json(response)
  } catch (error) {
    console.log("error", error)
    res.json({
      message: error.message
    })
  }
})

// API: Logout
app.post('/logout', async (req, res) => {
  const token = req.get('Authorization').split(' ')[1]
  const params = {
    AccessToken: token,
  }

  try {
    const response = await client.send(new GlobalSignOutCommand(params))
    res.json(response)
  } catch (error) {
    console.log("error", error)
    res.json({
      message: error.message
    })
  }
})

// API: Request forgot password
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body
  const params = {
    ClientId: CLIENT_ID,
    Username: email,
  }
  
  try {
    const response = await client.send(new ForgotPasswordCommand(params))
    res.json(response)
  } catch (error) {
    console.log("error", error)
    res.json({
      message: error.message
    })
  }
})

// API: Confirm forgot password
app.post('/confirm-forgot-password', async (req, res) => {
  const { email, code, password } = req.body
  const params = {
    ClientId: CLIENT_ID,
    Username: email,
    ConfirmationCode: code,
    Password: password,
  }

  try {
    const response = await client.send(new ConfirmForgotPasswordCommand(params))
    res.json(response)
  } catch (error) {
    console.log("error", error)
    res.json({
      message: error.message
    })
  }
})

// API: Resend email
app.post('/resend-email', async (req, res) => {
  const { email } = req.body
  const params = {
    UserPoolId: USER_POOL_ID,
    Username: email,
    TemporaryPassword: 'TempResend1234!',
    DesiredDeliveryMediums: [DeliveryMediumType.EMAIL],
    MessageAction: 'RESEND',
  }

  try {
    const response = await client.send(new AdminCreateUserCommand(params))
    res.json(response)
  } catch (error) {
    console.log("error", error)
    res.json({
      message: error.message
    })
  }
})

// API: Get user
app.post('/get-user', async (req, res) => {
  const { email } = req.body
  const params = {
    UserPoolId: USER_POOL_ID,
    Username: email
  }

  try {
    const response = await client.send(new AdminGetUserCommand(params))
    res.json(response)
  } catch (error) {
    console.log("error", error)
    res.json({
      message: error.message
    })
  }
})

app.listen(port, () => {
  console.log(`Server is running on port 3000`);
});