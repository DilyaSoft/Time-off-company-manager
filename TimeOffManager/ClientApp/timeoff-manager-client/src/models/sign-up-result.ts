import { Token } from "./jwt-token";

export interface SignUpResult {
    success: boolean;
    message: string;
    token: Token;
}