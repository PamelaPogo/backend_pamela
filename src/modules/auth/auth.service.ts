import { HttpException, Injectable } from '@nestjs/common';
import { LoginAuthDto } from './dto/login-auth.dto';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { User } from '../users/entities/user.entity';
import { hash, compare } from 'bcrypt';

@Injectable()
export class AuthService {

    constructor(private jwtService: JwtService,
               @InjectRepository(User) private userRepository: Repository<User>){}

    async funRegister(objUser: RegisterAuthDto){
        const {password}=objUser //capturamos solo password de todo el objetivo
        //console.log("Antes: ", objUser)
        const plainToHash=await hash(password, 12) //para encriptar la contraseña
        //console.log(plainToHash) //imprime el hash

        objUser={...objUser, password:plainToHash}
        //almacena todos los datos execpto el password que fue sacado y guardado un nuevo password
        //console.log("Despues: ",objUser)

        return this.userRepository.save(objUser) //para guardar en la BDD
    }
    
    async login(credenciales: LoginAuthDto){

        const {email,password}=credenciales //en este camo necesitamos los 2 campos
        const user=await this.userRepository.findOne({
            where:{
                email: email
            }
        })
        //si no existe el usuario lanzamos una excepcion
        if (!user) return new HttpException('Usuario no encontrado',404);

        const verificarPass = await compare(password, user.password) 

        if (!verificarPass) throw new HttpException('Password inválido', 401)
        
        let payload={email:user.email, id:user.id}
        const token=this.jwtService.sign(payload)
        return {user:user, token:token}
    }
}
