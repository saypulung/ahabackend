import path from 'path';
import fs from 'fs';

import express, { Request, Response, NextFunction, Express } from 'express';
import * as dotenv from 'dotenv';
import { auth, requiresAuth } from 'express-openid-connect';
import { header, validationResult } from 'express-validator';
import { PrismaClient, user_profiles_gender, Refer } from '@prisma/client';
import bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import FormData = require('form-data');
import Mailgun from 'mailgun.js';
import axios from 'axios';
import ImageKit from 'imagekit';
import { UploadResponse, IKCallback } from 'imagekit/dist/libs/interfaces';
import multer from 'multer';
const upload = multer({ dest: 'uploads/' });
import helmet from 'helmet';
import swaggerJSDoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

dotenv.config();

import signupRequest from './requests/signup_request';
import profileRequest from './requests/profile_request';

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

const parsePrismaDate = (date: Date) => {
    const y = date.getFullYear();
    const m = (date.getMonth() + 1).toString().padStart(2, '0');
    const d = (date.getDate()).toString().padStart(2, '0');
    return `${y}-${m}-${d}`;
};

const app: Express = express();
app.use(express.static(path.join(__dirname, '..', 'public')));

// Helmet use can be adjust later
app.use(helmet.frameguard());
app.use(helmet.referrerPolicy());
app.use(helmet.ieNoOpen());
const swaggerDoc = require('../swagger.json');
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDoc));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(
    auth({
        authRequired: false,
        auth0Logout: true,
        issuerBaseURL: process.env.AUTH0_DOMAIN,
        baseURL: `${process.env.APP_URL}`,
        clientID: process.env.AUTH0_CLIENT_ID,
        secret: process.env.APP_SECRET,
        routes: {
            login: false,
            callback: undefined,
        },
    })
);
app.use(express.urlencoded({ extended: false }));
app.get('/login', async (req: Request, res: Response, next: NextFunction) => {
    res.oidc.login({
        returnTo: `${process.env.APP_URL}/profile`,
        authorizationParams: {
            redirect_uri: `${process.env.APP_URL}/callback`
        }
    })
});
app.get('/callback', async (req: Request, res: Response, next: NextFunction) => {
    console.log(req.body);
    console.log(req.params);
    console.log(req.query);
    res.send('cek console');
});
app.post('/callback', async (req: Request, res: Response, next: NextFunction) => {
    console.log(req.body);
    console.log(req.params);
    console.log(req.query);
    res.send('cek console');
});
app.get('/', async (req: Request, res: Response, next: NextFunction) => {
    const page = 'home';
    let user = undefined;
    let autenticated = false;
    if (req.oidc.isAuthenticated()) {
        user = req.oidc.user;
        autenticated = true;
        const prisma = new PrismaClient();
        const now: string = parsePrismaDate(new Date());
        const isLoginToday: Array<Number> | null = await prisma.$queryRaw`SELECT id FROM user_activities WHERE user_id=${user?.sub} and login_at=${new Date(now)} LIMIT 1;`;

        if (!isLoginToday?.length) {
            await prisma.userActivity.create({
                data: {
                    user_id: user?.sub,
                    email: user?.email,
                    login_at: new Date(),
                    given_name: user?.given_name,
                    family_name: user?.family_name,
                }
            })
        }

        await prisma.$disconnect();
    }
    return res.render('parts_layout', { title: 'Work at Aha', page, user, autenticated });
});
app.get('/me', async (req: Request, res: Response, next: NextFunction) => {
    console.log(req.oidc.accessToken);
    if (!req.oidc.isAuthenticated()) {
        return res.status(403).json({ message: 'Access unauthorized' });
    }
    let user = req.oidc.user;
    const objUser = {
        nickname: user?.nickname,
        given_name: user?.given_name,
        family_name: user?.family_name,
        email: user?.email,
        picture: user?.picture,
        email_verified: user?.email_verified,
        sub: '',
        birthday: '',
        gender: undefined,
        phone: '',
    };
    const prisma = new PrismaClient({
        log: ['query', 'info', 'warn', 'error'],
    });
    const ids: any = user?.sub.split('|');
    objUser.sub = ids[0];
    const profile = await prisma.profile.findFirst({
        where: {
            source: ids[0] === 'auth0' ? 'database' : ids[0],
            source_id: ids[1],
        }
    });
    if (profile) {
        Object.assign(objUser, profile);
    }
    if (profile?.birthday) {
        objUser.birthday = parsePrismaDate(profile?.birthday);
    }
    await prisma.$disconnect();
    return res.status(200).json({ message: 'Success load your profile', data: objUser });
});
app.get('/profile', requiresAuth(), async (req: Request, res: Response, next: NextFunction) => {
    let page = 'profile';
    if (!req.oidc.isAuthenticated()) {
        return res.redirect('/');
    }

    let user = req.oidc.user;
    const objUser = {
        nickname: user?.nickname,
        given_name: user?.given_name,
        family_name: user?.family_name,
        email: user?.email,
        picture: user?.picture,
        email_verified: user?.email_verified,
        sub: '',
        birthday: '',
        gender: undefined,
        phone: '',
    };
    const prisma = new PrismaClient({
        log: ['query', 'info', 'warn', 'error'],
    });
    const ids: any = user?.sub.split('|');
    objUser.sub = ids[0];
    const profile = await prisma.profile.findFirst({
        where: {
            source: ids[0] === 'auth0' ? 'database' : ids[0],
            source_id: ids[1],
        }
    });
    if (profile) {
        Object.assign(objUser, profile);
    }
    if (profile?.birthday) {
        objUser.birthday = parsePrismaDate(profile?.birthday);
    }
    await prisma.$disconnect();
    return res.render('parts_layout', { title: 'Work at Aha', page, user: objUser });
});
app.get('/signup', async (req: Request, res: Response, next: NextFunction) =>
    res.render('parts_layout', { title: 'Signup', page: 'signup' })
);

app.post('/signup', [...signupRequest, async (req: Request, res: Response, next: NextFunction) => {
    if (req.oidc.isAuthenticated()) {
        return res.status(403).json({ message: 'You are already logged in' });
    }
    const errors = validationResult(req);
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
    // use Auth0 Management API to sync own-DB into Auth0 user database
    await axios.post(`${process.env.AUTH0_DOMAIN}/api/v2/users`, jsonData, {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${auth0RequestToken as string}`,
        }
    }).then(async ({ data }) => {
        console.log(data);
        let user = null;
        // check is it success when send a user to Auth0
        if (data) {
            user = data;
            const prisma = new PrismaClient();
            const userId: number = Number(user.user_id.split('|')[1]);
            const mailtoken = crypto.randomBytes(36).toString('hex');
            await prisma.user.update({
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
            genders.set('0', user_profiles_gender.Male);
            genders.set('1', user_profiles_gender.Female);
            genders.set('2', user_profiles_gender.Rather_not_say);
            genders.set('3', user_profiles_gender.Custom);

            const refers = new Map();
            refers.set('0', Refer.Male);
            refers.set('1', Refer.Female);
            refers.set('2', Refer.Other);

            await prisma.profile.create({
                data: {
                    source_id: `${userId}`,
                    source: 'database',
                    given_name: req.body.given_name,
                    phone: req.body.phone,
                    family_name: req.body.family_name,
                    gender: genders.has(req.body.gender) ? genders.get(req.body.gender) : null,
                    gender_custom: req.body.custom_gender,
                    refer_as: req.body.refer_as !== '' && refers.has(req.body.refer_as) ?
                        refers.get(req.body.refer_as) : null,
                    nickname: user.nickname,
                    picture: `https://ui-avatars.com/api/?name=${[req.body.given_name, req.body.family_name].join('+').replace(' ', '')}`
                }
            });
            await prisma.$disconnect();
            mailgunClient.messages.create(process.env.MAILGUN_DOMAIN as string, {
                from: process.env.MAILGUN_FROM as string,
                to: [email],
                subject: 'Verify you account',
                html: emailVerification(email, [req.body.given_name, req.body.family_name].join(' '), mailtoken),
            })
                .then(msg => console.log(msg))
                .catch(err => console.error(err));
            return res.status(201).json({ message: 'Success create a user', data: user });
        } else {
            return res.status(500).json({ message: 'Sorry, we have problem to create your profile. Try again later' });
        }
    }).catch( err => {
        console.log(err);
        return res.status(500).json({message: 'Error when creating your account'});
    });

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
                await prisma.$disconnect();
                if (req.oidc.user) {
                    req.oidc.user.email_verified = true;
                }
                return res.redirect('/dashboard');
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
                await prisma.$disconnect();
                if (req.oidc.user) {
                    req.oidc.user.email_verified = true;
                }
                return res.redirect('/dashboard');
            }
        } else {
            await prisma.$disconnect();
            return res.send('Account is not found');
        }
    }
    return res.send('Account not found');
});
app.get('/dashboard', requiresAuth(), async (req: Request, res: Response, next: NextFunction) => {
    console.log(req.cookies);
    if (!req.oidc.user?.email_verified) {
        return res.status(403).render('parts_layout', { page: 'dashboard_denied', title: 'Account not verified' });
    } else {
        return res.render('parts_layout', { page: 'dashboard', title: 'Dashboard' });
    }
});
app.post('/update-avatar', requiresAuth(), upload.single('image'), async (req: Request, res: Response, next: NextFunction) => {
    const imagekit = new ImageKit({
        publicKey: process.env.IMAGEKIT_PUBLIC_KEY as string,
        privateKey: process.env.IMAGEKIT_PRIVATE_KEY as string,
        urlEndpoint: process.env.IMAGEKIT_URL as string
    });
    const user = req.oidc.user;
    const subs = user?.sub.split('|');
    subs[0] = subs[0] === 'auth0' ? 'database' : subs[0];
    const file = fs.readFileSync(path.join(__dirname, '..', req.file?.path as string));
    imagekit.upload({
        file: file,
        fileName: req.file?.originalname as string,
        extensions: [
            {
                name: "google-auto-tagging",
                maxTags: 5,
                minConfidence: 95
            }
        ]
    }).then(async response => {
        const prisma = new PrismaClient({
            log: ['query', 'info', 'warn', 'error'],
        });
        const profile = await prisma.profile.findFirst({
            where: {
                source: subs[0],
                source_id: subs[1],
            }
        });
        if (profile) {
            await prisma.profile.update({
                where: {
                    id: profile.id,
                },
                data: {
                    picture: response.url,
                },
            });
        } else {
            await prisma.profile.create({
                data: {
                    source: subs[0],
                    source_id: subs[1],
                    picture: response.url,
                    nickname: user?.nickname,
                    given_name: user?.given_name,
                    family_name: user?.family_name,
                }
            });
        }
        await prisma.$disconnect();
        return res.status(201).json({ message: 'Success change avatar', url: response.url });
    }).catch(error => {
        return res.status(403).json({ message: 'Unable to upload', error: error.message });
    });
});
app.put('/update-profile', [requiresAuth(), ...profileRequest, async (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(401).json(parseErrorValidation(errors.array()));
    }
    const user = req.oidc.user;
    const subs = user?.sub.split('|');
    subs[0] = subs[0] === 'auth0' ? 'database' : subs[0];
    const genders = new Map();
    genders.set('0', user_profiles_gender.Male);
    genders.set('1', user_profiles_gender.Female);
    genders.set('2', user_profiles_gender.Rather_not_say);
    genders.set('3', user_profiles_gender.Custom);

    const refers = new Map();
    refers.set('0', Refer.Male);
    refers.set('1', Refer.Female);
    refers.set('2', Refer.Other);

    const prisma = new PrismaClient();
    const profile = await prisma.profile.findFirst({
        where: {
            source: subs[0],
            source_id: `${subs[1]}`,
        }
    });

    const birthday = req.body.birthday ? req.body.birthday : null;
    let newDoB = null;
    if (birthday !== null) {
        newDoB = new Date(Date.parse(birthday));
    }
    if (profile) {
        await prisma.profile.update({
            where: {
                id: profile.id,
            },
            data: {
                given_name: req.body.given_name,
                family_name: req.body.family_name,
                gender: genders.has(req.body.gender) ? genders.get(req.body.gender) : null,
                gender_custom: req.body.custom_gender,
                refer_as: req.body.refer_as !== '' && refers.has(req.body.refer_as) ?
                    refers.get(req.body.refer_as) : null,
                bio: req.body.bio,
                birthday: newDoB,
                phone: req.body.phone,
            }
        });
    } else {
        await prisma.profile.create({
            data: {
                source_id: `${subs[1]}`,
                source: subs[0],
                given_name: req.body.given_name,
                family_name: req.body.family_name,
                gender: genders.has(req.body.gender) ? genders.get(req.body.gender) : null,
                gender_custom: req.body.custom_gender,
                refer_as: req.body.refer_as !== '' && refers.has(req.body.refer_as) ? refers.get(req.body.refer_as) : null,
                bio: req.body.bio,
                birthday: req.body.birthday,
            }
        });
    }
    await prisma.$disconnect();
    return res.status(201).json({ message: 'Success update profile' });
}]);
app.get('/reset-password', requiresAuth(), async (req: Request, res: Response, next: NextFunction) => {
    const users = req.oidc.user;
    const subs = users?.sub.split('|');
    if (subs[0] !== 'auth0') {
        return res.redirect('/profile');
    }
    return res.render('parts_layout', { page: 'change_password', title: 'Change password' });
});
app.post('/reset-password', [requiresAuth(), async (req: Request, res: Response, next: NextFunction) => {
    const users = req.oidc.user;
    const subs = users?.sub.split('|');
    const prisma = new PrismaClient();
    if (subs[0] !== 'auth0') {
        return res.redirect('/profile');
    }
    let userDb = null;
    if (req.body.current_password) {
        userDb = await prisma.user.findFirst({
            where: {
                id: Number(subs[1]),
            }
        });
        const isPasswordMatched: boolean = await bcrypt.compare(req.body.current_password, userDb?.password as string);
        if (!isPasswordMatched) {
            return res.status(401).json({ current_password: 'Make sure that your current password is correct' });
        }
    } else {
        return res.status(401).json({ current_password: 'Current password is required' });
    }
    if (req.body.new_password) {
        const value = req.body.new_password;
        let validPassword = true;
        const indicators: number[] = [];

        // has lower case and uppercase
        if ((/[A-Z]/.test(value)) && (/[a-z]/.test(value))) {
            indicators.push(0);
        } else {
            validPassword = false;
        }
        // contains numbers
        if (/[0-9]/.test(value)) {
            indicators.push(1);
        } else {
            validPassword = false;
        }

        // min 8 , max 200
        if (/^.{8,200}$/.test(value)) {
            indicators.push(2);
        } else {
            validPassword = false;
        }

        // has special characters
        if (/[#?!@$%^&*\-+~'"()_=`]/.test(value)) {
            indicators.push(3);
        } else {
            validPassword = false;
        }
        if (!validPassword) {
            return res.status(401).json({ new_password: 'Password is not secure' });
        }
    } else {
        return res.status(401).json({ new_password: 'Please provide new password' });
    }
    if (req.body.password_confirm) {
        if (req.body.new_password !== req.body.password_confirm) {
            return res.status(401).json({ password_confirm: 'Password does not match' });
        }
    } else {
        return res.status(401).json({ password_confirm: 'Please retype new password' });
    }
    const hashPassword = await bcrypt.hashSync(req.body.new_password, 10);
    await prisma.user.update({
        where: {
            id: userDb?.id,
        },
        data: {
            password: hashPassword,
        }
    });
    await prisma.$disconnect();
    return res.status(201).json({ message: 'Success change password' });
}]);
app.post('/pre-register-sso', async (req: Request, res: Response, next: NextFunction) => {
    const key = req.header('Kunci');
    if (key !== process.env.AUTH0_ARTIFICIAL_SECRET) {
        return res.status(401).send('Invalid key');
    }
    const email = req.body.email;
    if (email) {
        const prisma = new PrismaClient();
        const userByEmail = await prisma.user.findFirst({
            where: {
                email: email,
            }
        });
        await prisma.$disconnect();
        if (userByEmail) {
            return res.status(403).send('You have register with user and password. Please login using the email that you have registered.');
        } else {
            return res.status(200).send('Email can be used.');
        }
    } else {
        return res.status(403).send('Please provide email address.');
    }
});
app.get('/users', [requiresAuth(), async (req: Request, res: Response, next: NextFunction) => {
    const timeNow = new Date().getTime();
    if (timeNow >= auth0ExpiredToken || auth0RequestToken == null) {
        await generateAuth0Token();
    }
    const params = {
        page: 0,
        per_page: 100,
        include_totals: true,
        sort: 'created_at:-1',
        fiels: 'user_id,email,given_name,family_name,created_at,updated_at,logins_count,last_login',
        include_fields: true,
    };
    const dataUsers = await axios.get(
        `${process.env.AUTH0_DOMAIN}/api/v2/users`,
        {
            params: params,
            headers: {
                'Authorization': `Bearer ${auth0RequestToken}`,
            }
        }
    );
    return res.status(200).json(dataUsers.data);
}]);
app.get('/user-statistic', [requiresAuth(), async (req: Request, res: Response, next: NextFunction) => {
    const timeNow = new Date().getTime();
    if (timeNow >= auth0ExpiredToken || auth0RequestToken == null) {
        await generateAuth0Token();
    }
    const params = {
        page: 0,
        per_page: 5,
        include_totals: true,
        sort: 'created_at:-1',
        fields: 'user_id,email,given_name,family_name,created_at,updated_at,logins_count,last_login',
        include_fields: true,
    };
    const dataUsers = await axios.get(
        `${process.env.AUTH0_DOMAIN}/api/v2/users`,
        {
            params: params,
            headers: {
                'Authorization': `Bearer ${auth0RequestToken}`,
            }
        }
    );
    const paramStats = {
        page: 0,
        per_page: 10,
        include_totals: true,
        sort: 'created_at:-1',
        fields: 'user_id,email,given_name,family_name,created_at,updated_at,logins_count,last_login',
        include_fields: true,
        search_engine: 'v2',
        q: 'last_login:2023-03-12',
    };
    const dataStatistic = await axios.get(
        `${process.env.AUTH0_DOMAIN}/api/v2/users`,
        {
            params: paramStats,
            headers: {
                'Authorization': `Bearer ${auth0RequestToken}`,
            }
        }
    );
    const prisma = new PrismaClient();
    interface countUser {
        total: Number,
    };
    const activeToday: Array<countUser> = await prisma.$queryRaw`select count(id) as total from user_activities where login_at=${parsePrismaDate(new Date)};`;
    const result = activeToday.length > 0 ? Number(activeToday[0].total) : 0;

    const dateNow = new Date();
    const dateStart = new Date();
    dateStart.setDate(dateNow.getDate() - 7);

    const activeThisWeek: Array<countUser> = await prisma.$queryRaw`select count(id) as total 
    from user_activities 
    where login_at between ${parsePrismaDate(dateStart)} and ${parsePrismaDate(dateNow)} 
    group by login_at;`;
    let resultThisWeek = 0;
    if (activeThisWeek.length) {
        let sum = 0;
        for (let val of activeThisWeek) {
            sum += Number(val.total);
        }
        resultThisWeek = sum / activeThisWeek.length;
    }
    return res.status(200).json({ total: dataUsers.data.total, today: result, thisweek: resultThisWeek });
}]);
app.get('/resend-verification', [requiresAuth(), async (req: Request, res: Response, next: NextFunction) => {
    const user = req.oidc.user;

    const prisma = new PrismaClient();
    const userId: number = Number(user?.sub.split('|')[1]);
    const mailtoken = crypto.randomBytes(36).toString('hex');
    await prisma.user.update({
        where: {
            id: userId,
        },
        data: {
            email_verified: false,
            token: mailtoken,
        },
    });
    await prisma.$disconnect();
    mailgunClient.messages.create(process.env.MAILGUN_DOMAIN as string, {
        from: process.env.MAILGUN_FROM as string,
        to: [user?.email],
        subject: 'Verify you account',
        html: emailVerification(user?.email, [user?.given_name, user?.family_name].join(' '), mailtoken),
    })
        .then(msg => {
            return res.send('Success sending email verification');
        })
        .catch(err => {
            return res.send('We have problem to resend email verification');
        });
}]);
app.post('/authorize', async (req: Request, res: Response, next: NextFunction) => {
    if (req.oidc.isAuthenticated()) {
        return res.status(403).json({ error: 'Authenticated', message: 'You are already authenticated' });
    }
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(403).json({ message: 'Please provide your username and password' });
    }
    const params = {
        grant_type: 'password',
        username,
        password,
        scope: '',
        client_id: process.env.AUTH0_API_CLIENT_ID,
        client_secret: process.env.AUTH0_API_SECRET,
        audience: `${process.env.AUTH0_DOMAIN}/api/v2/`,
    }
    await axios.post(`${process.env.AUTH0_DOMAIN}/oauth/token`, params, {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    })
        .then(response => {
            const exp = Date.now() + response.data.expires_in * 1000;
            console.log('exp', exp);
            const dateExpires = new Date(exp).toUTCString();
            res.setHeader('Set-Cookie', `appSession=${
                response.data.access_token}; Expires=${
                dateExpires}; Domain=aha.zonahijau.my.id`);
            return res.status(200).json({ access_token: response.data.access_token });
        }).catch(err => {
            return res.status(500).json(err.response.data);
        });
});
app.listen(
    Number(process.env.PORT),
    () => {
        console.log(`Running...${process.env.APP_URL}`);
        generateAuth0Token();
    });