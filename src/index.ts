import path from 'path';

import express, { Request, Response, NextFunction, Express } from 'express';
import * as dotenv from 'dotenv';
import { auth } from 'express-openid-connect';
import { validationResult } from 'express-validator';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import FormData = require('form-data');
import Mailgun from 'mailgun.js';
import axios from 'axios';

dotenv.config();

import signupRequest from './requests/signup_request';
let auth0RequestToken: string | null = null;
let auth0ExpiredToken = 0;

const mailgun = new Mailgun(FormData);
const mailgunClient = mailgun.client({
    username: 'api',
    key: process.env.MAILGUN_API_KEY as string,
});

const emailVerification = (email: string, name: string, token: string) => {
    let styleButton = 'style="border-radius: 8px;border: none;background-color: #4285f4;color: #fff;padding: 16px;margin: 10px 30px;';
    styleButton += 'text-decoration: none; border-radius: 8px;"';
    const styleBody = 'max-width: 400px; margin: 0 auto; border-radius: 8px; border: 1px solid #ddd;padding: 16px;';
    let body = `<html><head></head><body style="${styleBody}">`;
    body += `<h3>Hello <strong>${name}<strong>,</h3><br>`;
    body += '<p>Thank you for registering to our platform. ';
    body += 'Please verify your email to see all of the features in our platform.<p>';
    body += '<p>Click button below to verify your email</p>';
    body += `<a ${styleButton} href="http://143.42.78.22:3000/verify?token=${token}">Verify my account</a>`;
    body += `<br><br><p> or click link below if you can not click button above</p>`;
    body += `<a href="http://143.42.78.22:3000/verify?token=${token}">http://143.42.78.22:3000/verify?token=${token}</a>`;
    body += '</body></html>';
    return body;
};

const generateAuth0Token = async () => {
    const jsonData = JSON.stringify({
        client_id: process.env.AUTH0_API_CLIENT_ID,
        client_secret: process.env.AUTH0_API_SECRET,
        audience: `${process.env.AUTH0_DOMAIN}/api/v2/`,
        grant_type: 'client_credentials',
    });
    const { data } = await axios.post(`https://expressdemo.us.auth0.com/oauth/token`, jsonData, {
        headers: {
            'Content-Type': 'application/json',
        }
    });
    if (data) {
        auth0RequestToken = data.access_token;
        auth0ExpiredToken = new Date().getTime() + data.expires_in;
        return data;
    }
    return null;
};

const parseErrorValidation = (errors: any) => {
    const errorMsg = new Map();
    for (var err of errors) {
        // returnError[string(err.param)] = err.msg;
        errorMsg.set(err.param, err.msg);
    }
    return Object.fromEntries(errorMsg);
};

const app: Express = express();
app.use(express.static(path.join(__dirname, '..', 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(
    auth({
        authRequired: false,
        auth0Logout: true,
        issuerBaseURL: process.env.AUTH0_DOMAIN,
        baseURL: `${process.env.APP_URL}:${process.env.PORT}`,
        clientID: process.env.AUTH0_CLIENT_ID,
        secret: process.env.APP_SECRET,
        // routes: undefined,
    })
);
app.use(express.urlencoded({ extended: false }));

app.get('/', async (req: Request, res: Response, next: NextFunction) => {
    let page = 'home';
    let user = undefined;
    if (req.oidc.isAuthenticated()) {
        page = 'dashboard';
        user = req.oidc.user;
        console.log(user);
    }
    return res.render('parts_layout', { title: 'Work at Aha', page, user });
});
app.get('/signup', async (req: Request, res: Response, next: NextFunction) => {
    return res.render('parts_layout', { title: 'Signup', page: 'signup' });
});

app.post('/signup', [...signupRequest, async (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    console.log(req.body);
    if (!errors.isEmpty()) {
        return res.status(401).json(parseErrorValidation(errors.array()));
    }
    const { email, password } = req.body;
    const timeNow = new Date().getTime();
    if (timeNow >= auth0ExpiredToken || auth0RequestToken == null) {
        await generateAuth0Token();
    }
    const jsonData = JSON.stringify({
        email: email,
        password: password,
        connection: 'Username-Password-Authentication',
        verify_email: false,
        email_verified: false,
        blocked: false,
        user_metadata: {},
        app_metadata: {},
    });
    const data = await axios.post(`${process.env.AUTH0_DOMAIN}/api/v2/users`, jsonData, {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${auth0RequestToken as string}`,
        }
    });
    console.log(data);
    let user = null;
    if (data.status === 201) {
        user = data.data;
        const prisma = new PrismaClient();
        const userId: number = Number(user.user_id.split('|')[1]);
        const mailtoken = crypto.randomBytes(36).toString('hex');
        const updateUser = await prisma.user.update({
            where: {
                id: userId,
            },
            data: {
                email_verified: false,
                token: mailtoken,
            },
        });
        // just following google behavior
        const genders = new Map();
        genders.set('0', 'Male');
        genders.set('1', 'Female');
        genders.set('2', 'Rather not say');
        genders.set('3', 'Custom');
        
        const refers = new Map();
        refers.set('0', 'Male');
        refers.set('1', 'Female');
        refers.set('2', 'Other');
        
        const createUserProfile = await prisma.profile.create({
            data: {
                source_id: `${userId}`,
                source: 'database',
                given_name: req.body.given_name,
                family_name: req.body.family_name,
                gender: genders.has(req.body.gender) ? genders.get(req.body.gender) : null,
                gender_custom: req.body.custom_gender,
                refer_as: req.body.refer_as !== '' && refers.has(req.body.refer_as) ? refers.get(req.body.refer_as) : null,
                nickname: user.nickname,
                picture: `https://ui-avatars.com/api/?name=${[req.body.given_name,req.body.family_name].join('+').replace(' ','')}`
            }
        });

        mailgunClient.messages.create(process.env.MAILGUN_DOMAIN as string, {
            from: process.env.MAILGUN_FROM as string,
            to: [email],
            subject: 'Verify you account',
            html: emailVerification(email, [req.body.given_name, req.body.family_name].join(' '), mailtoken),
        })
            .then(msg => console.log(msg))
            .catch(err => console.error(err));
        return res.status(201).json({message: 'Success create a user', data: user});
    } else {
        return res.status(500).json({ message: 'Sorry, we have problem to create your profile. Try again later' });
    }
}]);

app.get('/verify', async (req: Request, res: Response, next: NextFunction) => {
    const token = req.query.token;
    if (token !== '') {
        const prisma = new PrismaClient();
        const findUser = await prisma.user.findMany({
            take: 1,
            where: {
                token: token as string,
            }
        });
        if (findUser && findUser.length == 1) {
            if (findUser[0].email_verified) {
                return res.send('Your account is already verified');
            }
            const updateUser = await prisma.user.update({
                where: {
                    id: findUser[0].id,
                },
                data: {
                    email_verified: true,
                    token: null,
                },
            });
            if (updateUser) {
                return res.send('Verify account successfuly');
            }
        } else {
            return res.send('Account is not found');
        }
    }
    return res.send('Account not found');
});

app.listen(
    Number(process.env.PORT),
    '0.0.0.0',
    () => {
        console.log(`Running...${process.env.APP_URL}:${process.env.PORT}`);
        generateAuth0Token();
    });