import { ApiProperty } from '@nestjs/swagger';
import { IsEthereumAddress, IsNotEmpty, IsString } from 'class-validator';

export class GetNonceQueryDto {
  @ApiProperty({
    description: 'Ethereum address of wallet (used for Binance Wallet)',
    example: '0x1234567890123456789012345678901234567890',
  })
  @IsEthereumAddress()
  @IsNotEmpty()
  address: string;
}

export class VerifySignatureDto {
  @ApiProperty({
    description: 'Ethereum address of wallet (used for Binance Wallet)',
    example: '0x1234567890123456789012345678901234567890',
  })
  @IsNotEmpty()
  address: string;

  @ApiProperty({
    description: 'Signed message',
    example: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  })
  @IsString()
  @IsNotEmpty()
  signature: string;
}

export class AuthResponseDto {
  @ApiProperty({
    description: 'JWT token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
  })
  access_token: string;
  
  @ApiProperty({
    description: 'User information',
  })
  user: {
    id: string;
    username: string;
    email: string;
    address: string;
  };
}