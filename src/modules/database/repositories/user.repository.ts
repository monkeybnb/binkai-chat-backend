import { DataSource, Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { InjectDataSource } from '@nestjs/typeorm';

export class UserRepository extends Repository<User> {
  constructor(@InjectDataSource() private dataSource: DataSource) {
    super(User, dataSource.createEntityManager());
  }

  async findByUsername(username: string): Promise<User | null> {
    return this.findOne({ where: { username } });
  }

  async findByAddress(address: string): Promise<User | null> {
    const normalizedAddress = address.startsWith('0x') ? address : address.toLowerCase();
    return this.findOne({ where: { address: normalizedAddress } });
  }
}
