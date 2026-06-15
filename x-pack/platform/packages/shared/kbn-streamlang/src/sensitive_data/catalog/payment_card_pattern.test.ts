/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { groupedDigitTail, groupedDigitTailRange } from './payment_card_pattern';

describe('payment_card_pattern helpers', () => {
  it('groupedDigitTail derives repeat count from total and prefix digit lengths', () => {
    expect(groupedDigitTail(16, 2)).toBe('[ .-]?(?:[0-9][ .-]?){13}[0-9]');
    expect(groupedDigitTail(15, 2)).toBe('[ .-]?(?:[0-9][ .-]?){12}[0-9]');
    expect(groupedDigitTail(14, 3)).toBe('[ .-]?(?:[0-9][ .-]?){10}[0-9]');
  });

  it('groupedDigitTailRange covers inclusive total digit bounds', () => {
    expect(groupedDigitTailRange(1, 13, 19)).toBe('[ .-]?(?:[0-9][ .-]?){11,17}[0-9]');
    expect(groupedDigitTailRange(4, 12, 19)).toBe('[ .-]?(?:[0-9][ .-]?){7,14}[0-9]');
  });

  it('groupedDigitTail allows a separator immediately after a multi-digit IIN prefix', () => {
    const discover6011Tail = groupedDigitTail(16, 4);
    expect(new RegExp(`6011${discover6011Tail}`).test('6011 5326 4094 4700')).toBe(true);
    expect(new RegExp(`6011${discover6011Tail}`).test('6011111111111117')).toBe(true);

    const maestroTail = groupedDigitTailRange(4, 12, 19);
    expect(new RegExp(`6304${maestroTail}`).test('6304 7512 3005 8764')).toBe(true);
    expect(new RegExp(`6304${maestroTail}`).test('6304000000000000')).toBe(true);
  });
});
