// Built-in demo transcripts so the dashboard is playable with no backend dataset
// and no live call integration. Each "plays" turn-by-turn through the pipeline.
//
// The digital-arrest sample quotes the mule account 50100294471882, which is
// seeded in the backend fraud graph — so playing it produces a real cross-victim
// match rather than a staged one.

export const SAMPLE_TRANSCRIPTS = [
  {
    id: 'digital_arrest_repeat',
    label: 'Digital Arrest — CBI impersonation (repeat scammer)',
    scamType: 'digital_arrest',
    expectation: 'scam',
    note: 'Quotes a mule account already in the fraud graph → cross-victim match.',
    turns: [
      { speaker: 'caller', text: 'Good morning, am I speaking with Rajesh Kumar? This is Inspector Vikram Rathore from CBI Mumbai, badge number 4471.', timestamp: '00:04' },
      { speaker: 'user', text: 'Yes, this is Rajesh. What is this regarding?', timestamp: '00:11' },
      { speaker: 'caller', text: 'A parcel booked in your name to Taiwan was intercepted by Customs. It contained 400 grams of MDMA and four fake passports.', timestamp: '00:24' },
      { speaker: 'user', text: 'What? I never sent any parcel. This must be a mistake.', timestamp: '00:33' },
      { speaker: 'caller', text: 'Sir, your Aadhaar number was used. An FIR number MUM/CBI/2024/8871 has been registered against you for money laundering.', timestamp: '00:48' },
      { speaker: 'caller', text: 'You are under digital arrest from this moment. Do not disconnect this video call and do not inform anyone, not even your family. This is a classified investigation.', timestamp: '01:07' },
      { speaker: 'user', text: 'Please, I have not done anything wrong. I am a schoolteacher.', timestamp: '01:18' },
      { speaker: 'caller', text: 'To prove your funds are clean, you must transfer your balance to the RBI verification account 50100294471882. It will be refunded within two hours after verification.', timestamp: '01:39' },
      { speaker: 'caller', text: 'If you delay, a non-bailable warrant will be issued and you will be arrested tonight. Do it now.', timestamp: '01:52' },
    ],
  },
  {
    id: 'kyc_fraud',
    label: 'KYC Fraud — account-block pressure',
    scamType: 'kyc_fraud',
    expectation: 'scam',
    note: 'OTP extraction under a KYC-expiry pretext.',
    turns: [
      { speaker: 'caller', text: 'Hello, I am calling from your bank. Your KYC has expired and your account will be blocked within two hours.', timestamp: '00:05' },
      { speaker: 'user', text: 'Oh no, what do I need to do?', timestamp: '00:12' },
      { speaker: 'caller', text: 'Just complete a quick verification. I am sending an OTP to your number now. Please read it out to me.', timestamp: '00:23' },
      { speaker: 'user', text: 'Okay, it says 4-4-1-2...', timestamp: '00:31' },
      { speaker: 'caller', text: 'Good. And to update the app, please install AnyDesk from the Play Store so I can guide you.', timestamp: '00:44' },
    ],
  },
  {
    id: 'lottery_prize',
    label: 'Lottery Prize — advance fee',
    scamType: 'lottery_prize',
    expectation: 'scam',
    note: 'Prize you never entered; pay GST to release it.',
    turns: [
      { speaker: 'caller', text: 'Congratulations sir! Your number has won 25 lakh rupees in the KBC Lucky Draw!', timestamp: '00:03' },
      { speaker: 'user', text: 'Really? But I never entered any draw.', timestamp: '00:10' },
      { speaker: 'caller', text: 'It is an automatic draw of all subscribers. To release the prize you only need to pay the 5% GST clearance of Rs 12,500.', timestamp: '00:22' },
      { speaker: 'caller', text: 'Send it via UPI to kbcclaim2024@ybl and the full amount will be credited in 24 hours.', timestamp: '00:34' },
    ],
  },
  {
    id: 'legit_bank',
    label: 'Legitimate — bank fraud alert (hard negative)',
    scamType: 'none',
    expectation: 'legitimate',
    note: 'Looks alarming, but never asks for OTP or a transfer. Must NOT be flagged.',
    turns: [
      { speaker: 'caller', text: "Hi, this is Priya from HDFC Bank's fraud monitoring team. Am I speaking with Mr. Anand?", timestamp: '00:04' },
      { speaker: 'user', text: 'Yes, speaking.', timestamp: '00:08' },
      { speaker: 'caller', text: 'We flagged a transaction of Rs 45,000 on your card ending 4412 at an electronics store in Hyderabad ten minutes ago. Can you confirm if this was you?', timestamp: '00:21' },
      { speaker: 'user', text: 'No, I am in Pune. I did not make that.', timestamp: '00:28' },
      { speaker: 'caller', text: 'Understood, I am blocking the card now. I will never ask you for an OTP, PIN, or password, and no bank employee ever will.', timestamp: '00:42' },
      { speaker: 'caller', text: 'Your dispute reference is DSP-88214. If you would like to verify this call, please hang up and call the number on the back of your card.', timestamp: '00:57' },
    ],
  },
  {
    id: 'legit_delivery',
    label: 'Legitimate — courier delivery OTP (hard negative)',
    scamType: 'none',
    expectation: 'legitimate',
    note: 'Involves an OTP, but for a real delivery. Must NOT be flagged.',
    turns: [
      { speaker: 'caller', text: 'Hello, this is Ravi from Delhivery. I am at your gate with a parcel from Amazon.', timestamp: '00:03' },
      { speaker: 'user', text: 'Oh yes, I was expecting that. I will come down.', timestamp: '00:09' },
      { speaker: 'caller', text: 'No problem sir. Could you share the delivery OTP that came to your phone so I can mark it delivered?', timestamp: '00:18' },
      { speaker: 'user', text: 'Sure, it is 7-7-2-1.', timestamp: '00:24' },
      { speaker: 'caller', text: 'Thank you, delivered. Have a good day!', timestamp: '00:29' },
    ],
  },
];
