import { StyleSheet, ScrollView, Pressable } from 'react-native';
import { router } from 'expo-router';
import { ThemedText } from '@/components/themed-text';
import { ThemedView } from '@/components/themed-view';
import { SafeAreaView } from 'react-native-safe-area-context';

export default function HomeScreen() {
  return (
    <SafeAreaView style={{ flex: 1 }}>
      <ScrollView contentContainerStyle={styles.container}>
        {/* Header, Description, Features (unchanged) */}

        {/* Action Buttons */}
        <ThemedView style={styles.actions}>
          <Pressable
            style={({ pressed }) => [
              styles.button,
              styles.loginButton,
              pressed && styles.buttonPressed,
            ]}
            onPress={() => router.push('/login')}
          >
            <ThemedText style={styles.buttonText}>Log In</ThemedText>
          </Pressable>

          <Pressable
            style={({ pressed }) => [
              styles.button,
              styles.registerButton,
              pressed && styles.buttonPressed,
            ]}
            onPress={() => router.push('/register')}
          >
            <ThemedText style={styles.buttonText}>Create Account</ThemedText>
          </Pressable>
        </ThemedView>

        {/* Footer (unchanged) */}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  // ... other styles remain the same
  button: {
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
  },
  loginButton: {
    backgroundColor: '#2563eb',
  },
  registerButton: {
    backgroundColor: '#10b981',
  },
  buttonPressed: {
    opacity: 0.8,
  },
  buttonText: {
    color: '#ffffff',
    fontSize: 18,
    fontWeight: '600',
  },
  // ... footer etc.
});