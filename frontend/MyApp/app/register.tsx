import { View, Text } from 'react-native';
import { Link } from 'expo-router';

export default function Login() {
  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      <Text>Register</Text>
      <Link href="/">Back to Home</Link>
    </View>
  );
}