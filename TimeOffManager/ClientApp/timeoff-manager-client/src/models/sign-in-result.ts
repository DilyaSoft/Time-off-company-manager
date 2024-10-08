import { Token } from "./jwt-token";

export interface SignInResult {
    success: boolean;
    message: string;
    token: Token;
}
