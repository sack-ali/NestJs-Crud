import { Controller, Get, UseGuards, Req, Body, Patch} from '@nestjs/common';
import {AuthGuard} from '@nestjs/passport';
import {Request} from 'express';
import {JwtGuard} from '../auth/guard';
import {GetUser} from '../auth/decorator';
import {User} from '@prisma/client'
import { EditUserDto } from './dto';
import { UserService } from './user.service';

@UseGuards(JwtGuard)
@Controller('users')
export class UserController {
    constructor(private userService: UserService) {}
    @Get('me')
    getMe(@GetUser() user: User, @GetUser('email') email: string) {
        console.log({
            email,
        })
        return user;
    }

    @Patch()
    editUser(
      @GetUser('id') userId: number,
      @Body() dto: EditUserDto,
    ) {
      return this.userService.editUser(userId, dto);
    }
}
