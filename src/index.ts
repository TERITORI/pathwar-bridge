import express, { Express, Request, Response } from 'express'
import dotenv from 'dotenv'
const Cosmos = require('@keplr-wallet/cosmos');
import jwt from 'jsonwebtoken'
import cors from 'cors'
import { PrismaClient } from '@prisma/client'
import fs from "fs";

dotenv.config()

const app: Express = express()
const port = process.env.PORT
const prisma = new PrismaClient()
const privateKEY = fs.readFileSync('private.key', 'utf8');

app.use(express.json())


app.use(cors())

app.get('/', (req: Request, res: Response) => {
  res.send('Express + TypeScript Server')
})

app.post('/token', async (req: Request, res: Response) => {
  try {
    const { pubkey, address, signed, signature } = req.body

    if (!pubkey || !address || !signed || !signature) {
      return res.status(400).json({ error: 'Missing required fields' })
    }

    const prefix = "tori"
    const signatureBuffer = Buffer.from(signature, 'base64')
    const uint8Signature = new Uint8Array(signatureBuffer)
    const pubKeyValueBuffer = Buffer.from(pubkey, 'base64')
    const pubKeyUint8Array = new Uint8Array(pubKeyValueBuffer)
    const valid = Cosmos.verifyADR36Amino(prefix, address, signed, pubKeyUint8Array, uint8Signature)

    if (!valid) {
      return res.status(403).json({ error: 'Signature verification failed' })
    }

    let user = await prisma.user.findUnique({
      where: {
        address: address,
      },
    })

    if (!user) {
      user = await prisma.user.create({
        data: {
          address: address,
          sub: 'tori|' + address
        },
     })
    }



    const payload = {
      preferred_username: user.address,
      email: user.address + '@tori.com',
      email_verified: true,
      given_name: '',
      family_name: '',
    }

    const signOptions: jwt.SignOptions = {
      issuer: 'http://localhost:3000',
      subject: user.sub,
      expiresIn: '30s',
      algorithm: 'RS256',
    }


    const token = jwt.sign(payload, privateKEY, signOptions)

    res.json({ token })
  } catch (error) {
    console.log(error)
    res.status(500).json({ error })
  }
})

app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at http://localhost:${port}`)
})
