import { UserRepository } from '@/database/repositories';
import { ResponseMessage } from '@/shared/decorators/response-message.decorator';
import { ApiBaseResponse } from '@/shared/swagger/decorator/api-response.decorator';
import {
  Controller,
  ForbiddenException,
  Get,
  HttpStatus,
  UseInterceptors,
  Param,
  BadRequestException,
  Inject,
  forwardRef,
  Query,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags, ApiQuery } from '@nestjs/swagger';
import { FormatResponseInterceptor } from '../interceptors';
import { WalletGateway } from '../../websocket/wallet.gateway';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    private userRepository: UserRepository,
    @Inject(forwardRef(() => WalletGateway))
    private readonly walletGateway: WalletGateway
  ) {}

  funErr() {
    console.log('Test error ');
    try {
      throw new Error('Test error');
    } catch (e) {
      throw e;
    }
  }

  @Get('')
  @ResponseMessage('Hello')
  @ApiOperation({ summary: 'Basic health check endpoint' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'API is healthy',
  })
  async healthCheck() {
    return 1;
  }

  @Get('check-db')
  @ApiOperation({ summary: 'Check database connection' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Database connection is healthy',
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Database connection failed',
  })
  async checkDB() {
    return await this.userRepository.findOne({ where: {} });
  }

  @Get('throw')
  @ApiOperation({ summary: 'Testing error handling' })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'This endpoint always throws an error',
  })
  throwError() {
    this.funErr();
  }

  @Get('wallet-address/:threadId')
  @ApiOperation({ summary: 'Get wallet address for a specific threadId' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Successfully got wallet address',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid threadId or no active connection',
  })
  async getWalletAddress(@Param('threadId') threadId: string) {
    try {
      console.log('🔍 Getting wallet address for threadId:', threadId);
      const address = await this.walletGateway.getWalletAddress(threadId, 'mainnet');
      console.log('✅ Got wallet address:', address);
      return { address };
    } catch (error) {
      console.error('🔴 Error getting wallet address:', error);
      throw new BadRequestException(error.message);
    }
  }

  @Get('sign-message/:threadId')
  @ApiOperation({ summary: 'Sign a message using wallet' })
  @ApiQuery({
    name: 'message',
    required: true,
    type: String,
    description: 'Message to sign',
    example: 'Hello, world!'
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Message signed successfully',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid threadId or signing failed',
  })
  async signMessage(
    @Param('threadId') threadId: string,
    @Query('message') message: string
  ) {
    try {
      console.log('🔍 Signing message for threadId:', threadId);
      const signature = await this.walletGateway.signMessage(threadId, message);
      console.log('✅ Message signed successfully');
      return { signature };
    } catch (error) {
      console.error('🔴 Error signing message:', error);
      throw new BadRequestException(error.message);
    }
  }

  @Get('sign-transaction/:threadId')
  @ApiOperation({ summary: 'Sign a transaction using wallet' })
  @ApiQuery({
    name: 'to',
    required: true,
    type: String,
    description: 'Recipient address',
    example: '0x1234567890123456789012345678901234567890'
  })
  @ApiQuery({
    name: 'value',
    required: true,
    type: String,
    description: 'Amount to send',
    example: '0.1'
  })
  @ApiQuery({
    name: 'gas',
    required: true,
    type: String,
    description: 'Gas limit',
    example: '21000'
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Transaction signed successfully',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid threadId or signing failed',
  })
  async signTransaction(
    @Param('threadId') threadId: string,
    @Query('to') to: string,
    @Query('value') value: string,
    @Query('gas') gas: string
  ) {
    try {
      console.log('🔍 Signing transaction for threadId:', threadId);
      const signedTransaction = await this.walletGateway.signTransaction(threadId, { to, value, gas });
      console.log('✅ Transaction signed successfully');
      return { signedTransaction };
    } catch (error) {
      console.error('🔴 Error signing transaction:', error);
      throw new BadRequestException(error.message);
    }
  }
}
