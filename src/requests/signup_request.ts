import { body } from "express-validator";
import { PrismaClient } from '@prisma/client';

const signupRequest = [
    body('given_name', 'empty name')
        .trim()
        .isLength({ min: 3 })
        .withMessage('Name at least 3 characters')
        .isLength({ max: 30 })
        .withMessage('max 30')
        .escape(),
    body('family_name', 'empty family name')
        .optional({ checkFalsy: true })
        .trim()
        .isLength({ max: 30 })
        .withMessage('max 30')
        .escape(),
    body('email')
        .isEmail()
        .withMessage('Provide a valid email')
        .custom(async (value: string) => {
            const prisma = new PrismaClient({
                log: ['query', 'info', 'warn', 'error'],
            });
            const findUser = await prisma.user.findMany({
                where: {
                    email: {
                        equals: `${value}`,
                    },
                },
            });
            console.log(findUser);
            await prisma.$disconnect();
            if (findUser && findUser.length > 0) {
                throw new Error('Email is already exist');
            }
            return true;
        }).normalizeEmail(),
    body('phone').optional({ checkFalsy: true })
        .custom((value) => {
            if (value.match(/[0-9() +-]/g).length == value.length) {
                return true;
            }
            else {
                return false;
            }
        })
        .withMessage('please provide a valid number phone'),
    body('password', 'please provide your password')
        .custom((value) => {
            if (value == '') {
                throw new Error('please provide your password');
            }
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
                throw new Error('Password is not secure');
            }
            return validPassword;
        }),
    body('password_confirm')
        .custom((value, { req }) => value === req.body.password)
        .withMessage('password confirm does not match with password')

];
export default signupRequest;