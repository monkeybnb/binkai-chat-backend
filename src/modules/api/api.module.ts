import { Module, OnApplicationBootstrap } from '@nestjs/common';
import { DatabaseModule } from '@/database';
import { HealthController, AuthController, UserController, ThreadController, ChatController } from '@/api/controllers';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { QueueModule } from '@/queue/queue.module';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { CustomThrottlerGuard } from './guards/custom-throttler.guard';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { redisStore } from 'cache-manager-redis-store';
import { CacheModule, CacheStore } from '@nestjs/cache-manager';
import { configAuth } from './configs/auth';
import { configCache } from './configs/cache';
import { FormatResponseInterceptor, HttpCacheInterceptor } from './interceptors';
import { BusinessModule } from '@/business/business.module';
import { WebsocketModule } from 'modules/websocket/websocket.module';

const controllers = [HealthController, AuthController, UserController, ThreadController, ChatController];

@Module({
  imports: [
    ThrottlerModule.forRoot({
      ttl: 60,
      limit: process.env.APP_ENV === 'production' ? 60 : 600,
    }),
    DatabaseModule,
    QueueModule,
    BusinessModule,
    WebsocketModule,
    CacheModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => {
        const urlRedis = `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}/${process.env.REDIS_DATABASE}`;
        return {
          ttl: configService.get('cache.api.cache_ttl'),
          store: (await redisStore({
            url: urlRedis,
            ttl: Number(configService.get('cache.api.cache_ttl')) / 1000,
          })) as unknown as CacheStore,
        };
      },
    }),
    ConfigModule.forRoot({
      isGlobal: true,
      expandVariables: true,
      load: [configAuth, configCache],
    }),
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('auth.jwt.jwt_secret_key'),
        global: true,
      }),
      inject: [ConfigService],
    }),
    ThrottlerModule.forRoot({
      ttl: 60,
      limit: 10000,
    }),
  ],
  controllers: [...controllers],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: HttpCacheInterceptor,
    },
    // ...services,
  ],
  exports: [],
})
export class ApiModule implements OnApplicationBootstrap {
  constructor() {}

  async onApplicationBootstrap() {}
}
