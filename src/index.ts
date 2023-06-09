import express, { Express, Request, Response } from 'express'
import dotenv from 'dotenv'
const Cosmos = require('@keplr-wallet/cosmos');
import jwt from 'jsonwebtoken'
import cors from 'cors'

dotenv.config()

const app: Express = express()
const port = process.env.PORT

const SECRET_KEY = process.env.SECRET_KEY
app.use(express.json())


app.use(cors())

app.get('/', (req: Request, res: Response) => {
  res.send('Express + TypeScript Server')
})

app.post('/token', async (req: Request, res: Response) => {
  try {
    const { pubkey, address, signed, signature } = req.body

    const prefix = "tori"
    const signatureBuffer = Buffer.from(signature, 'base64');
    const uint8Signature = new Uint8Array(signatureBuffer);
    const pubKeyValueBuffer = Buffer.from(pubkey, 'base64');
    const pubKeyUint8Array = new Uint8Array(pubKeyValueBuffer);
    const valid = Cosmos.verifyADR36Amino(prefix, address, signed, pubKeyUint8Array, uint8Signature);

    if (!valid) {
      return res.status(403).json({ error: 'Signature verification failed' })
    }

    const payload = {
      preferred_username: pubkey,
      email: 'hello@world.com',
      email_verified: true,
      given_name: '',
      family_name: '',
    }

    const signOptions: jwt.SignOptions = {
      issuer: 'http://localhost:3000',
      subject: 'tori|532cb4a4-7ad7-40a5-826a-c8272af2d9f3',
      expiresIn: '30s',
      algorithm: 'HS256',
    }


    const token = jwt.sign(payload, SECRET_KEY as string, signOptions)

    res.json({ token })
  } catch (error) {
    console.log(error)
    res.status(500).json({ error })
  }
})

app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at http://localhost:${port}`)
})
