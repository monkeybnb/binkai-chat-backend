import { Body, Controller, Get, HttpStatus, Post, Query, ValidationPipe } from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AuthService } from '@/business/auth/auth.service';
import { GetNonceQueryDto, VerifySignatureDto } from '../dtos';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get('nonce')
  @ApiOperation({ summary: 'Get nonce for wallet signature' })
  @ApiQuery({
    name: 'address',
    description: 'Ethereum address of wallet (used for Binance Wallet)',
    example: '0x1234567890123456789012345678901234567890',
    required: true,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Return nonce',
  })
  async getNonce(@Query('address', new ValidationPipe({ transform: true })) address: string) {
    return this.authService.getNonce(address);
  }

  @Post('login')
  @ApiOperation({ summary: 'Verify wallet signature and login' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Return access token',
  })
  async verifySignature(@Body() verifySignatureDto: VerifySignatureDto) {
    return this.authService.verifySignature(
      verifySignatureDto.address,
      verifySignatureDto.signature,
    );
  }
} 