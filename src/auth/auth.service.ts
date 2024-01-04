import { ForbiddenException, Injectable } from "@nestjs/common";
import {PrismaService} from "../prisma/prisma.service";
import {AuthDto} from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { error } from "console";
import { dot } from "node:test/reporters";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from '@nestjs/config';



@Injectable ({})
export class AuthService {
    constructor(private prisma: PrismaService, 
                private jwt: JwtService,
                private configService: ConfigService) {

    }
   async signup (dto: AuthDto) {

    try {

        const hash = await argon.hash(dto.password);

        const user = await this.prisma.user.create({
            data: {
                email:dto.email,
                hash,
            },
        });

        return this.signToken(user.id, user.email);

    } catch(error) {
        if(error instanceof PrismaClientKnownRequestError) {
            if(error.code === 'P2002') {
                throw new ForbiddenException(
                    'credentials taken',
                );
            }
        }
    }
   
        
    }  
    async signin (dto: AuthDto) {
        const user =
         await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        if(!user) 
            throw new ForbiddenException(
                'credential incorrect',
            );
        const pwMatches = await argon.verify(user.hash, dto.password);
        if(!pwMatches) 
        throw new ForbiddenException(
            'credential incorrect', 
            );
 
         return this.signToken(user.id, user.email); }

          
        
            
        async signToken(userId: number, email: string): Promise<{ access_token: string }> {
            const payload = {
                sub: userId,
                email,
            };
            const secret = this.configService.get<string>('JWT_SECRET')

            const  token = await this.jwt.signAsync(payload, {
                expiresIn: '15m',
                secret: secret,
            },);

           return {access_token: token};
        }
    
}