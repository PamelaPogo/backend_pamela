import { ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginAuthDto } from './dto/login-auth.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { Body, Controller, Post } from '@nestjs/common';

@ApiTags('auth')
@Controller('auth')
export class AuthController {

    constructor(private authService: AuthService){
    }
    @Post ('register')
    registerUser(@Body()userObj : RegisterAuthDto){
        console.log(userObj);
        return this.authService.funRegister(userObj);
    }
    @Post('login')
    login(@Body() credenciales: LoginAuthDto){
        return this.authService.login(credenciales)

    }
}
