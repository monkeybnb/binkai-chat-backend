import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserRepository } from '../../database/repositories/user.repository';
import { ethers } from 'ethers';
import { User } from '../../database/entities/user.entity';

@Injectable()
export class AuthService {
  constructor(
    private userRepository: UserRepository,
    private jwtService: JwtService,
  ) {}

  async getNonce(address: string): Promise<{ nonce: number }> {
    const normalizedAddress = address.startsWith('0x') ? address : address?.toLowerCase();
    // Check if wallet address already exists in the system
    let user = await this.userRepository.findByAddress(normalizedAddress);

    console.log('user', {
      user,
      normalizedAddress,
    });

    // If not exists, create new user
    if (!user) {
      user = new User();
      user.address = normalizedAddress;
      user.username = normalizedAddress;
      user.nonce = Math.floor(Math.random() * 1000000);
      await this.userRepository.save(user);
    } else {
      // Update new nonce
      user.nonce = Math.floor(Math.random() * 1000000);
      await this.userRepository.save(user);
    }

    return { nonce: user.nonce };
  }

  async verifySignature(address: string, signature: string) {
    const normalizedAddress = address.startsWith('0x') ? address : address?.toLowerCase();
    // Find user by wallet address
    const user = await this.userRepository.findByAddress(normalizedAddress);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // Create message for signature verification
    const message = `Sign this message to login with nonce: ${user.nonce}`;

    try {
      // Recover address from signature
      const recoveredAddress = ethers.verifyMessage(message, signature);

      // Check if recovered address matches the user's address
      if (recoveredAddress !== normalizedAddress && recoveredAddress.toLowerCase() !== normalizedAddress.toLowerCase()) {
        throw new HttpException('Invalid signature', HttpStatus.UNAUTHORIZED);
      }

      // Update new nonce
      user.nonce = Math.floor(Math.random() * 1000000);
      await this.userRepository.save(user);

      // Create JWT token
      const payload = { sub: user.id, address: user.address };
      const access_token = this.jwtService.sign(payload);

      return {
        access_token,
        user: {
          id: user.id,
          username: user.username,
          address: normalizedAddress,
        },
      };
    } catch (error) {
      // Handle signature verification error
      throw new HttpException(
        'Signature verification failed',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }
}