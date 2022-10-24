import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { randomBytes, scrypt as _scrypt } from 'crypto';
import { promisify } from 'util';
import { UsersService } from './users.service';

const scrypt = promisify(_scrypt);

@Injectable()
export class AuthService {
  constructor(private userService: UsersService) {}

  async signup(email: string, password: string) {
    // see if email in use
    const users = await this.userService.find(email);

    if (users.length) {
      throw new BadRequestException('email in use');
    }
    // hash the user password
    // generate a salt

    const salt = randomBytes(8).toString('hex');
    // Generate the salt and the password hash

    const hash = (await scrypt(password, salt, 32)) as Buffer;

    //  Join the hashed result and the salt togheter

    const result = salt + '.' + hash.toString('hex');

    // create a new user and save

    const user = await this.userService.create(email, result);
    // return user
    return user;
  }

  async signin(email: string, password: string) {
    const [user] = await this.userService.find(email);
    if (!user) {
      throw new NotFoundException('Email Not found');
    }

    const [salt, storedHash] = user.password.split('.');
    const hash = (await scrypt(password, salt, 32)) as Buffer;

    if (storedHash !== hash.toString('hex')) {
      throw new BadRequestException('Invalid Password');
    }
    return user;
  }
}
