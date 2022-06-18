package cidr.security

import java.lang.Long.max
import java.lang.Long.min

class CidrRequests(cidrIpAddressList: List<String>) {
    private var constantPrefixLength = 0
    var unauthorizedIpAddresses: MutableList<IpRange> = mutableListOf()

    init {
        cidrIpAddressList.forEach {
            if (it.contains("/")) {
                val (ip, stringCidr) = it.split('/')
                val ipAddress = IPAddress(ip)
                constantPrefixLength = stringCidr.toInt()
                unauthorizedIpAddresses.addRange(cidrRangeCalculate(ipAddress))
            } else {
                throw IllegalArgumentException("only CIDR format is Allowed")
            }
        }
    }

    private fun cidrRangeCalculate(ipAddress: IPAddress): IpRange {
        val fullBinaryRepresentation = ipAddress.binaryIpAddressArray?.joinToString("")
        val ipRange = rangeIp(fullBinaryRepresentation, constantPrefixLength)
        val startRange = ipRange.first.chunked(8)
        val endRange = ipRange.second.chunked(8)
        val startRangeIP = IPAddress(startRange.binaryToDecimal().joinToString("."))
        val endRangeIp = IPAddress(endRange.binaryToDecimal().joinToString("."))
        return IpRange(LongRange(startRangeIP.ipToLong(), endRangeIp.ipToLong()))
    }

    private fun rangeIp(stringBytes: String?, host_bits: Int): Pair<String, String> {
        val bits = 32 - host_bits
        val startRange = stringBytes?.substring(0, host_bits) + "0".repeat(bits)
        val endRange = stringBytes?.substring(0, host_bits) + "1".repeat(bits)
        return Pair(startRange, endRange)
    }

    private fun List<String>.binaryToDecimal() =
        this.map { it.toInt(2) }


    fun isAllowed(incomingIp: String): Boolean = !isInRange(incomingIp)

    private fun MutableList<IpRange>.addRange(range: IpRange) {
        if (this.isEmpty()) {
            this.add(range)
        } else {
            with(listIterator()) {
                var added = false
                while (!added) {
                    if (!hasNext()) {
                        add(range)
                        added = true
                    } else {
                        val value = next()
                        if (isOverlapping(range, value)) {
                            val minRange = min(range.range.first, value.range.first)
                            val maxRange = max(range.range.last, value.range.last)
                            val newRange = IpRange(
                                LongRange(minRange, maxRange)
                            )
                            set(newRange)
                            added = true
                        }
                    }
                }
            }
        }
    }


    private fun isOverlapping(range1: IpRange, range2: IpRange): Boolean =
        (range1.range.first <= range2.range.last && range2.range.first <= range1.range.last)


    private fun isInRange(ipAddress: String): Boolean {
        val ipAddressLong = IPAddress(ipAddress).ipToLong()
        return unauthorizedIpAddresses.any { it.range.contains(ipAddressLong) }
    }
}

data class IpRange(val range: LongRange)
