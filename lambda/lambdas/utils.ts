import {
    APIGatewayRequestAuthorizerEvent,
    APIGatewayAuthorizerEvent,
    PolicyDocument,
    APIGatewayProxyEvent,
    StatementEffect,
} from "aws-lambda";

import axios from "axios";
import jwt from 'jsonwebtoken';
import jwkToPem from "jwk-to-pem";

export type CookieMap = { [key: string]: string } | undefined;
export type JwtToken = { sub: string; email: string } | null;

export type Jwk = {
    keys: {
        alg: string;
        e: string;
        kid: string;
        kty: "RSA"; // Ensuring kty is always "RSA"
        n: string;
        use: string;
    }[];
};

export const parseCookies = (
    event: APIGatewayRequestAuthorizerEvent | APIGatewayProxyEvent
) => {
    if (!event.headers || !event.headers.Cookie) {
        return undefined;
    }

    const cookiesStr = event.headers.Cookie;
    const cookiesArr = cookiesStr.split(";");

    const cookieMap: CookieMap = {};

    for (let cookie of cookiesArr) {
        const cookieSplit = cookie.trim().split("=");
        cookieMap[cookieSplit[0]] = cookieSplit[1];
    }

    return cookieMap;
};

export const verifyToken = async (
    token: string,
    userPoolId: string | undefined,
    region: string
): Promise<JwtToken> => {
    try {
        const decodedHeader = jwt.decode(token, { complete: true }) as { header: { kid: string } } | null;

        if (!decodedHeader || !decodedHeader.header) {
            throw new Error("Invalid token");
        }

        const kid = decodedHeader.header.kid;
        const url = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
        const { data }: { data: Jwk } = await axios.get(url);

        const key = data.keys.find(key => key.kid === kid);
        if (!key) {
            throw new Error("No matching key found");
        }

        const pem = jwkToPem(key);
        return jwt.verify(token, pem, { algorithms: ["RS256"] }) as JwtToken;
    } catch (err) {
        console.error("Token verification failed:", err);
        return null;
    }
};

export const createPolicy = (
    event: APIGatewayAuthorizerEvent,
    effect: StatementEffect
): PolicyDocument => {
    return {
        Version: "2012-10-17",
        Statement: [
            {
                Effect: effect,
                Action: "execute-api:Invoke",
                Resource: [event.methodArn],
            },
        ],
    };
};
