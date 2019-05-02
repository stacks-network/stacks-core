import { assert, expect } from 'chai';
import * as main from '../index';

describe('main', () => {
  it('example', () => {
    main.doLog();
    const thing = true;
    assert.isTrue(thing, 'works');
  });
});
