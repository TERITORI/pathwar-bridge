import express, { Express, Request, Response } from 'express'
import dotenv from 'dotenv'
import { Secp256k1, Secp256k1Signature, sha256 } from '@cosmjs/crypto'
import { fromBase64 } from '@cosmjs/encoding'
import { serializeSignDoc } from '@cosmjs/amino'
import jwt from 'jsonwebtoken'
import cors from 'cors'

dotenv.config()

const app: Express = express()
const port = process.env.PORT

const SECRET_KEY = process.env.SECRET_KEY
const CORS_FRONT_URL = process.env.CORS_FRONT_URL

app.use(
  cors({
    origin: CORS_FRONT_URL,
  })
)

app.get('/', (req: Request, res: Response) => {
  res.send('Express + TypeScript Server')
})

app.post('/token', async (req: Request, res: Response) => {
  const { pubkey, signed, signature } = req.body

  const valid = await Secp256k1.verifySignature(
    Secp256k1Signature.fromFixedLength(fromBase64(signature.signature)),
    sha256(serializeSignDoc(signed)),
    pubkey
  )

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
    subject: '532cb4a4-7ad7-40a5-826a-c8272af2d9f3',
    expiresIn: '30s',
    algorithm: 'RS256',
  }

  const token = jwt.sign(payload, SECRET_KEY as string, signOptions)

  res.json({ token })
})

app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at http://localhost:${port}`)
})
