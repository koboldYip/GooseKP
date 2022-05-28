import lombok.Data;
import lombok.SneakyThrows;
import org.pcap4j.core.*;
import org.pcap4j.packet.EthernetPacket;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@Data
public class GOOSE {

    private ByteBuffer destination = ByteBuffer.allocate(6);
    private ByteBuffer source = ByteBuffer.allocate(6);
    private ByteBuffer type = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x88, (byte) 0xB8});

    private ByteBuffer appID = ByteBuffer.allocate(2).put(new byte[]{0x00, 0x01});
    private ByteBuffer length = ByteBuffer.allocate(2);
    private ByteBuffer reserved1 = ByteBuffer.allocate(2).put(new byte[]{0x00, 0x00});
    private ByteBuffer reserved2 = ByteBuffer.allocate(2).put(new byte[]{0x00, 0x00});
    private ByteBuffer goosePdu = ByteBuffer.allocate(3).put(new byte[]{0x61, (byte) 0x81, (byte) 0x8A});
    private ByteBuffer timeAllowedToLive = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x81, 0x05});
    private ByteBuffer t = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x84, 0x08});
    private ByteBuffer stNum = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x85, 0x05});
    private ByteBuffer sqNum = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x86, 0x05});
    private ByteBuffer simulation = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x87, 0x01});
    private ByteBuffer confRev = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x88, 0x05});
    private ByteBuffer ndsCom = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x89, 0x01});
    private ByteBuffer numDatSetEntries = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x8A, 0x05});

    private ByteBuffer bool = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x83, 0x01});
    private ByteBuffer int32 = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x85, 0x05});
    private ByteBuffer float32 = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x87, 0x05});

    private ByteBuffer goCBRef = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x80});
    private ByteBuffer datSet = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x82});
    private ByteBuffer goID = ByteBuffer.allocate(2).put(new byte[]{(byte) 0x83});

    private ByteBuffer allDate = ByteBuffer.allocate(2).put(new byte[]{(byte) 0xAB});

    private ByteBuffer valueGoCBRef;
    private ByteBuffer valueDatSet;
    private ByteBuffer valueGoID;

    private ByteBuffer valueStNum = ByteBuffer.allocate(5);
    private ByteBuffer valueSqNum = ByteBuffer.allocate(5);
    private ByteBuffer valueSimulation = ByteBuffer.allocate(1);
    private ByteBuffer valueConfRev = ByteBuffer.allocate(5);
    private ByteBuffer valueNdsCom = ByteBuffer.allocate(1);

    private ByteBuffer valueBool = ByteBuffer.allocate(1).put(new byte[]{0x00});
    private ByteBuffer valueInt32 = ByteBuffer.allocate(5).put(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00});
    private ByteBuffer valueFloat32 = ByteBuffer.allocate(5).put(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00});

    private ByteBuffer valueTimeAllowedToLive = ByteBuffer.allocate(5).put(new byte[]{0x00, 0x00, 0x00, 0x00, 0x06});
    private ByteBuffer valueT = ByteBuffer.allocate(8);
    private ByteBuffer valueNumDatSetEntries = ByteBuffer.allocate(5);

    private ByteBuffer valueAllDate;

    private List<Item> dat = new ArrayList<>();

    private ByteBuffer buffer;

    private int time = 4;
    private int delay = 2000;

    private int lenGoose;
    private int lenAllowTime;
    private int lenSq;
    private int lenData;
    private int data;
    private int conf;
    private int sq;
    private int st;

    private List<PcapNetworkInterface> ifs;
    private ScheduledExecutorService ses;
    private ScheduledFuture future;
    private Runnable runnable;
    private PcapHandle sendHandle;
    private EthernetPacket packet;
    private byte[] pack;

    @SneakyThrows
    public void createGOOSE(DataSet dataSet) {
        ifs = Pcaps.findAllDevs();
        PcapNetworkInterface activeInterface = null;
        for (PcapNetworkInterface pcapIface : ifs) {
            if (pcapIface != null && pcapIface.getName().contains(dataSet.getIface())) {
                activeInterface = pcapIface;
                break;
            }
        }
        assert activeInterface != null;
        sendHandle = activeInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
        createHeader(dataSet);
        createData(dataSet);
        createMessage();
    }

    @SneakyThrows
    private void createMessage() {

        runnable = () -> {
            future = ses.schedule(runnable, time, TimeUnit.MILLISECONDS);
            increaseParam();
            try {
                sendHandle.sendPacket(packet);
                valueSqNum = valueSqNum.putInt(1, ++sq);
            } catch (PcapNativeException | NotOpenException e) {
                e.printStackTrace();
            }
        };

        buffer = ByteBuffer.allocate(lenGoose);

        buffer.put(destination)
                .put(source)
                .put(type.array())
                .put(appID.array())
                .put(length.array())
                .put(reserved1.array())
                .put(reserved2.array())
                .put(goosePdu.array())
                .put(goCBRef.array())
                .put(valueGoCBRef.array())
                .put(timeAllowedToLive.array())
                .put(valueTimeAllowedToLive.array())
                .put(datSet.array())
                .put(valueDatSet.array())
                .put(goID.array())
                .put(valueGoID.array())
                .put(t.array())
                .put(valueT.array())
                .put(stNum.array())
                .put(valueStNum.array())
                .put(sqNum.array())
                .put(valueSqNum.array())
                .put(simulation.array())
                .put(valueSimulation.array())
                .put(confRev.array())
                .put(valueConfRev.array())
                .put(ndsCom.array())
                .put(valueNdsCom.array())
                .put(numDatSetEntries.array())
                .put(valueNumDatSetEntries.array())
                .put(allDate.array());
        dat.forEach(this::typeValue);
        ses = Executors.newSingleThreadScheduledExecutor();
        packet = EthernetPacket.newPacket(buffer.array(), 0, lenGoose);

        sendHandle.sendPacket(packet);
        valueSqNum = valueSqNum.putInt(1, ++sq);

        runnable.run();
    }

    private void typeValue(Item e) {
        switch (e.getType()) {
            case "Boolean" -> buffer.put(bool.array())
                    .put(convertingToByte(Boolean.valueOf(e.getValue())));

            case "Integer" -> buffer.put(int32.array())
                    .put(ByteBuffer.allocate(5).putInt(1, Integer.parseInt(e.getValue())).array());

            case "Float" -> buffer.put(float32.array())
                    .put(ByteBuffer.allocate(5).put(new byte[]{0x08})
                            .putFloat(Float.parseFloat(e.getValue())).array());

        }
    }

    private void createHeader(DataSet dataSet) {

        conf = 0;
        st = 0;
        sq = 0;
        st++;
        conf++;
        valueConfRev = valueConfRev.putInt(1, conf);
        valueStNum = valueStNum.putInt(1, st);
        valueDatSet = ByteBuffer.wrap(dataSet.getDatasetName().getBytes(StandardCharsets.UTF_8));

        valueT = valueT
                .putInt(1, (int) (Instant.now().getEpochSecond()))
                .putInt(2, Instant.now().getNano());

        for (int i = 0; i < 6; i++) {
            destination.put(i, (byte) Integer.parseInt(dataSet.getMacDestination().split(":")[i], 16));
        }
        for (int i = 0; i < 6; i++) {
            source.put(i, (byte) Integer.parseInt(dataSet.getMacSource().split(":")[i], 16));
        }

        valueGoCBRef = ByteBuffer.wrap(dataSet.getGoCbRef().getBytes(StandardCharsets.UTF_8));
        valueGoID = ByteBuffer.wrap(dataSet.getGoID().getBytes(StandardCharsets.UTF_8));

        datSet.put( (byte) valueDatSet.array().length);
        goCBRef.put( (byte) valueGoCBRef.array().length);
        goID.put( (byte) valueGoID.array().length);

    }

    private void createData(DataSet dataSet) {

        dat = dataSet.getItems();

        valueNumDatSetEntries = valueNumDatSetEntries.putInt(1, dat.size());

        lenAllowTime = destination.array().length +
                source.array().length +
                type.array().length +
                appID.array().length +
                length.array().length +
                reserved1.array().length +
                reserved2.array().length +
                goosePdu.array().length +
                goCBRef.array().length +
                valueGoCBRef.array().length +
                timeAllowedToLive.array().length;

        lenSq = lenAllowTime +
                valueTimeAllowedToLive.array().length +
                datSet.array().length +
                valueDatSet.array().length +
                goID.array().length +
                valueGoID.array().length +
                t.array().length +
                valueT.array().length +
                stNum.array().length +
                valueStNum.array().length +
                sqNum.array().length;

        lenData = lenSq +
                valueSqNum.array().length +
                simulation.array().length +
                valueSimulation.array().length +
                confRev.array().length +
                valueConfRev.array().length +
                ndsCom.array().length +
                valueNdsCom.array().length +
                numDatSetEntries.array().length +
                valueNumDatSetEntries.array().length;

        dat.forEach(this::lengthValue);
        allDate.put((byte) data);

        lenGoose += lenData + data;

        length.put((byte) (lenGoose - destination.array().length - source.array().length - type.array().length));

    }

    private void lengthValue(Item e) {
        switch (e.getType()) {
            case "Boolean" -> {
                lenGoose += bool.array().length + valueBool.array().length;
                data += bool.array().length + valueBool.array().length;
            }
            case "Integer" -> {
                lenGoose += int32.array().length + valueInt32.array().length;
                data += int32.array().length + valueInt32.array().length;
            }
            case "Float" -> {
                lenGoose += float32.array().length + valueFloat32.array().length;
                data += float32.array().length + valueFloat32.array().length;
            }
        }
    }

    @SneakyThrows
    private void increaseParam() {
        time = Math.min(time * 2, delay);
        valueTimeAllowedToLive = valueTimeAllowedToLive
                .putInt(1, (int) Math.min(time * 1.5, delay * 1.5));
        packet = EthernetPacket.newPacket(buffer.put(lenAllowTime, valueTimeAllowedToLive.array())
                .put(lenSq, valueSqNum.array()).array(), 0, lenGoose);
    }

    private byte[] convertingToByte(Boolean bool) {
        if (bool) {
            return new byte[]{0x01};
        } else {
            return new byte[]{0x00};
        }
    }

    public void setData(DataSet newData) {
        future.cancel(true);
        ses.shutdownNow();
        dat = newData.getItems();
        sq = 0;
        time = 4;
        valueT = valueT
                .putInt((int) (Instant.now().getEpochSecond()))
                .putInt(Instant.now().getNano());
        valueSqNum = valueSqNum.putInt(1, sq);
        valueTimeAllowedToLive = valueTimeAllowedToLive
                .putInt(1, 6);
        valueStNum = valueStNum.putInt(1, ++st);
        this.createMessage();
    }
}
