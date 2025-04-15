import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserRepository } from '../../database/repositories/user.repository';
import { ethers } from 'ethers';
import { User } from '../../database/entities/user.entity';
import * as nacl from 'tweetnacl';
import bs58 from 'bs58';

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

    console.log('🔍 [AuthService] [getNonce] user:', {
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
      let isValid = false;
      
      // Check if Ethereum address (starts with 0x)
      if (address.startsWith('0x')) {
        // Verify using ethers.js for Ethereum addresses
        const recoveredAddress = ethers.verifyMessage(message, signature);
        isValid = recoveredAddress.toLowerCase() === normalizedAddress.toLowerCase();
      } else {
        // Assume Solana address or other non-Ethereum blockchain
        try {
          // For Solana verification
          const messageBytes = new TextEncoder().encode(message);
          const signatureBytes = Buffer.from(signature, 'base64');
          const publicKeyBytes = bs58.decode(address);
          
          isValid = nacl.sign.detached.verify(
            messageBytes,
            signatureBytes,
            publicKeyBytes
          );
        } catch (verificationError) {
          console.log('🔴 [AuthService] [verifySignature] Verification error:', verificationError);
          isValid = false;
        }
      }

      if (!isValid) {
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
      console.log('🔴 [AuthService] [verifySignature] error:', error);
      // Handle signature verification error
      throw new HttpException(
        'Signature verification failed',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }
}