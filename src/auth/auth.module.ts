import {Module} from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import {PrismaModule} from "../prisma/prisma.module";
import { JwtModule } from '@nestjs/jwt'
import { ConfigModule } from "@nestjs/config";
import { JwtStrategy } from './strategy/jwt.strategy';
import { PassportModule } from '@nestjs/passport';



@Module({
    imports: [JwtModule.register({}), 
        PrismaModule,
        ConfigModule,
        PassportModule],
   
    controllers: [AuthController],
    providers: [AuthService, JwtStrategy],
    exports: [AuthService] 
 
})
 export class AuthModule {}