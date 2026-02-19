import React, { useState, useMemo } from 'react';
import { View, Text, TextInput, StyleSheet, FlatList, Platform, Pressable } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Ionicons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { NoiseBackground } from '@/components/NoiseBackground';
import { ServerCard } from '@/components/ServerCard';
import { SubscriptionModal } from '@/components/SubscriptionModal';
import { useVpn } from '@/lib/vpn-context';
import Colors from '@/constants/colors';

export default function ServersScreen() {
  const insets = useSafeAreaInsets();
  const { servers, selectedServer, selectServer, favoriteServerIds, toggleFavorite, isPremium, connect, disconnect, isConnected, isConnecting } = useVpn();
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'favorites' | 'premium'>('all');
  const [subscriptionVisible, setSubscriptionVisible] = useState(false);
  const [pendingServerName, setPendingServerName] = useState<string | undefined>();
  const topPadding = Platform.OS === 'web' ? 67 : insets.top;

  const filteredServers = useMemo(() => {
    let list = servers;
    if (filter === 'favorites') list = list.filter(s => favoriteServerIds.includes(s.id));
    if (filter === 'premium') list = list.filter(s => s.premium);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(s =>
        s.name.toLowerCase().includes(q) ||
        s.country.toLowerCase().includes(q) ||
        s.city.toLowerCase().includes(q)
      );
    }
    return list.sort((a, b) => a.ping - b.ping);
  }, [servers, filter, search, favoriteServerIds]);

  const handleServerSelect = (server: typeof servers[0]) => {
    if (server.premium && !isPremium) {
      setPendingServerName(server.name);
      setSubscriptionVisible(true);
      return;
    }
    if (isConnected || isConnecting) {
      disconnect();
    }
    selectServer(server);
    if (Platform.OS !== 'web') {
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    }
    setTimeout(() => connect(), 100);
  };

  const FilterChip = ({ label, value }: { label: string; value: typeof filter }) => (
    <Pressable
      style={[styles.chip, filter === value && styles.chipActive]}
      onPress={() => setFilter(value)}
    >
      <Text style={[styles.chipText, filter === value && styles.chipTextActive]}>{label}</Text>
    </Pressable>
  );

  const premiumCount = servers.filter(s => s.premium).length;
  const freeCount = servers.filter(s => !s.premium).length;

  return (
    <NoiseBackground>
      <View style={[styles.container, { paddingTop: topPadding }]}>
        <View style={styles.header}>
          <Text style={styles.title}>Servers</Text>
          <Text style={styles.subtitle}>
            {servers.length} locations{isPremium ? ' – All Unlocked' : ` (${freeCount} free, ${premiumCount} premium)`}
          </Text>
        </View>

        <View style={styles.searchContainer}>
          <Ionicons name="search" size={16} color={Colors.dark.textMuted} style={styles.searchIcon} />
          <TextInput
            style={styles.searchInput}
            value={search}
            onChangeText={setSearch}
            placeholder="Search locations..."
            placeholderTextColor={Colors.dark.textMuted}
          />
        </View>

        <View style={styles.filterRow}>
          <FilterChip label="All" value="all" />
          <FilterChip label="Favorites" value="favorites" />
          <FilterChip label="Premium" value="premium" />
        </View>

        <FlatList
          data={filteredServers}
          keyExtractor={(item) => item.id}
          renderItem={({ item }) => (
            <ServerCard
              server={item}
              isSelected={selectedServer?.id === item.id}
              isFavorite={favoriteServerIds.includes(item.id)}
              onSelect={() => handleServerSelect(item)}
              onToggleFavorite={() => toggleFavorite(item.id)}
              locked={item.premium && !isPremium}
            />
          )}
          contentContainerStyle={styles.listContent}
          showsVerticalScrollIndicator={false}
          ListEmptyComponent={
            <View style={styles.emptyContainer}>
              <Ionicons name="globe-outline" size={48} color={Colors.dark.textMuted} />
              <Text style={styles.emptyText}>No servers found</Text>
            </View>
          }
        />
      </View>

      <SubscriptionModal
        visible={subscriptionVisible}
        onClose={() => setSubscriptionVisible(false)}
        serverName={pendingServerName}
      />
    </NoiseBackground>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  header: {
    paddingHorizontal: 24,
    paddingTop: 12,
    paddingBottom: 8,
  },
  title: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 22,
    color: Colors.dark.text,
    letterSpacing: 2,
  },
  subtitle: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 13,
    color: Colors.dark.textMuted,
    marginTop: 4,
  },
  searchContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginHorizontal: 20,
    marginVertical: 12,
    backgroundColor: 'rgba(255,255,255,0.04)',
    borderRadius: 14,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.06)',
    paddingHorizontal: 14,
  },
  searchIcon: {
    marginRight: 8,
  },
  searchInput: {
    flex: 1,
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 14,
    color: Colors.dark.text,
    paddingVertical: 12,
  },
  filterRow: {
    flexDirection: 'row',
    paddingHorizontal: 20,
    gap: 8,
    marginBottom: 12,
  },
  chip: {
    paddingHorizontal: 16,
    paddingVertical: 7,
    borderRadius: 20,
    backgroundColor: 'rgba(255,255,255,0.04)',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.06)',
  },
  chipActive: {
    backgroundColor: 'rgba(0, 240, 255, 0.1)',
    borderColor: 'rgba(0, 240, 255, 0.3)',
  },
  chipText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: Colors.dark.textSecondary,
  },
  chipTextActive: {
    color: Colors.dark.accent,
  },
  listContent: {
    paddingTop: 4,
    paddingBottom: 100,
  },
  emptyContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingTop: 60,
    gap: 12,
  },
  emptyText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 14,
    color: Colors.dark.textMuted,
  },
});
