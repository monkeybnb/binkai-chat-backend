import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { DatabaseModule } from '../database/database.module';
import { ThreadService } from './services';
import { OpenAIService } from './services/openai.service';
import { ConfigModule } from '@nestjs/config';
import { UserService } from './services/user.service';
import { AiService } from './services/ai.service';
import { WalletService } from './services/wallet.service';
import OpenAI from 'openai';
import { WalletGateway } from 'modules/websocket/wallet.gateway';
import { Connection } from '@solana/web3.js';
import { ethers } from 'ethers';
  
const services = [ThreadService, OpenAIService, UserService, AiService, WalletService, WalletGateway];

@Module({
  imports: [DatabaseModule, AuthModule, ConfigModule],
  exports: [AuthModule, ...services],
  providers: [
    ...services,
    {
      provide: 'OPENAI',
      useFactory: () => {
        return new OpenAI({
          apiKey: process.env.OPENAI_API_KEY,
        });
      },
    },
    {
      provide: "SOLANA_CONNECTION",
      useFactory: () => {
        const rpc = process.env.RPC_URL;
        const connection = new Connection(rpc);
        return connection;
      },
      inject: [],
    },
    {
      provide: "BSC_CONNECTION",
      useFactory: () => {
        const rpc = process.env.BSC_RPC_URL;
        return new ethers.JsonRpcProvider(rpc);
      },
    },
    {
      provide: "ETHEREUM_CONNECTION",
      useFactory: () => {
        const rpc = process.env.ETHEREUM_RPC_URL;
        return new ethers.JsonRpcProvider(rpc);
      },
    },
  ],
})
export class BusinessModule {}
